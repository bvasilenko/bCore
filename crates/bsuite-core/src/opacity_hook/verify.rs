use std::path::Path;

use goblin::Object;
use goblin::mach::{Mach, MachO, MultiArch, SingleArch};

use crate::BsuiteCoreError;

use super::section::{OPACITY_SECTION_ELF, OPACITY_SECTION_PE};
use super::types::{SCHEMA_VERSION, TierEvidence};

const MACHO_SEGNAME: &str = "__DATA";
const MACHO_SECTNAME: &str = "__BSUITE_OPACITY";

pub fn verify_tier_evidence(
    binary_path: &Path,
    expected_tier_id: &str,
) -> Result<TierEvidence, BsuiteCoreError> {
    let bytes = std::fs::read(binary_path).map_err(|e| {
        BsuiteCoreError::OpacitySectionMissing(format!("{}: {e}", binary_path.display()))
    })?;
    let section_bytes = extract_section(&bytes, &binary_path.display().to_string())?;
    let content = std::str::from_utf8(&section_bytes)
        .map_err(|e| BsuiteCoreError::OpacityTomlParseFailed(e.to_string()))?;
    validate_tier_evidence_toml(content, expected_tier_id)
}

pub fn validate_tier_evidence_toml(
    content: &str,
    expected_tier_id: &str,
) -> Result<TierEvidence, BsuiteCoreError> {
    let evidence: TierEvidence = toml::from_str(content)
        .map_err(|e| BsuiteCoreError::OpacityTomlParseFailed(e.to_string()))?;
    if evidence.schema_version != SCHEMA_VERSION {
        return Err(BsuiteCoreError::OpacitySchemaMismatch {
            expected: SCHEMA_VERSION,
            found: evidence.schema_version,
        });
    }
    if evidence.tier_id != expected_tier_id {
        return Err(BsuiteCoreError::OpacityTierMismatch {
            expected: expected_tier_id.to_owned(),
            found: evidence.tier_id,
        });
    }
    Ok(evidence)
}

fn extract_section(bytes: &[u8], path_display: &str) -> Result<Vec<u8>, BsuiteCoreError> {
    let object = Object::parse(bytes)
        .map_err(|e| BsuiteCoreError::OpacitySectionMissing(format!("{path_display}: {e}")))?;
    match object {
        Object::Elf(elf) => extract_elf_section(bytes, &elf),
        Object::Mach(Mach::Binary(macho)) => extract_macho_section(&macho),
        Object::Mach(Mach::Fat(multi)) => extract_fat_macho_section(&multi),
        Object::PE(pe) => extract_pe_section(bytes, &pe),
        _ => Err(BsuiteCoreError::OpacitySectionMissing(format!(
            "{path_display}: unrecognized binary format"
        ))),
    }
}

fn extract_elf_section(bytes: &[u8], elf: &goblin::elf::Elf) -> Result<Vec<u8>, BsuiteCoreError> {
    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name) == Some(OPACITY_SECTION_ELF) {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            return bytes.get(start..end).map(|s| s.to_vec()).ok_or_else(|| {
                BsuiteCoreError::OpacitySectionMissing(format!(
                    "ELF section {OPACITY_SECTION_ELF}: offset out of bounds"
                ))
            });
        }
    }
    Err(BsuiteCoreError::OpacitySectionMissing(format!(
        "ELF section {OPACITY_SECTION_ELF} not found"
    )))
}

fn extract_macho_section(macho: &MachO) -> Result<Vec<u8>, BsuiteCoreError> {
    macho
        .segments
        .sections()
        .flatten()
        .find_map(|result| match result {
            Ok((section, data))
                if trim_macho_name(&section.sectname) == MACHO_SECTNAME
                    && trim_macho_name(&section.segname) == MACHO_SEGNAME =>
            {
                Some(Ok(data.to_vec()))
            }
            Ok(_) => None,
            Err(e) => Some(Err(BsuiteCoreError::OpacitySectionMissing(e.to_string()))),
        })
        .unwrap_or_else(|| {
            Err(BsuiteCoreError::OpacitySectionMissing(format!(
                "Mach-O section {MACHO_SEGNAME},{MACHO_SECTNAME} not found"
            )))
        })
}

fn extract_fat_macho_section(multi: &MultiArch) -> Result<Vec<u8>, BsuiteCoreError> {
    for i in 0..multi.narches {
        if let Ok(SingleArch::MachO(macho)) = multi.get(i) {
            if let Ok(data) = extract_macho_section(&macho) {
                return Ok(data);
            }
        }
    }
    Err(BsuiteCoreError::OpacitySectionMissing(
        "fat Mach-O: no arch slice contains the opacity section".to_owned(),
    ))
}

fn extract_pe_section(bytes: &[u8], pe: &goblin::pe::PE) -> Result<Vec<u8>, BsuiteCoreError> {
    for section in &pe.sections {
        if pe_resolved_name(section) == OPACITY_SECTION_PE {
            let start = section.pointer_to_raw_data as usize;
            let end = start + section.size_of_raw_data as usize;
            return bytes.get(start..end).map(|s| s.to_vec()).ok_or_else(|| {
                BsuiteCoreError::OpacitySectionMissing(format!(
                    "PE section {OPACITY_SECTION_PE}: offset out of bounds"
                ))
            });
        }
    }
    Err(BsuiteCoreError::OpacitySectionMissing(format!(
        "PE section {OPACITY_SECTION_PE} not found"
    )))
}

fn trim_macho_name(b: &[u8; 16]) -> &str {
    let end = b.iter().position(|&x| x == 0).unwrap_or(16);
    std::str::from_utf8(&b[..end]).unwrap_or("")
}

fn pe_resolved_name(section: &goblin::pe::section_table::SectionTable) -> &str {
    if let Some(ref name) = section.real_name {
        name.as_str()
    } else {
        let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&section.name[..end]).unwrap_or("")
    }
}
