use std::path::Path;
use std::fs;
use goblin::{error, container};
use goblin::elf::{Elf, Sym};
use goblin::elf::program_header::ProgramHeader;
use goblin::pe::{PE, export};
use scroll::{Pread, Pwrite};
use std::io::{Cursor, Write};
use goblin::mach::load_command::SIZEOF_SECTION_32;
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_WRITE};
use goblin::pe::characteristic::IMAGE_FILE_32BIT_MACHINE;


const SIZEOF_IMAGE_DOS_HEADER: u64 = 0x40;
const SIZEOF_BUILTIN_SIGNATURE: u64 = 32;
const SIZEOF_IMAGE_NT_HEADERS: u64 = 0xf8;
const SIZEOF_IMAGE_SECTION_HEADER: u64 = 0x28;
const IMAGE_ORDINAL_FLAG: u32 = 0x80000000;

fn dlsym(elf: &Elf, name: &str) -> Option<Sym>
{
    for sym in elf.syms.iter() {
        if let Some(Ok(n)) = elf.strtab.get(sym.st_name) {
            if n == name {
                return Some(sym);
            }
        }
    }
    None
}

fn vm_to_offset(phdrs: &[ProgramHeader], address: u64) -> Option<u64> {
    for ph in phdrs {
        if address >= ph.p_vaddr {
            let offset = address - ph.p_vaddr;
            if offset < ph.p_memsz {
                return ph.p_offset.checked_add(offset);
            }
        }
    }
    None
}

fn fixup_rva_dwords(data: &mut [u8], offset: usize, delta: u32) -> error::Result<u32>
{
    let mut rva = data.pread_with::<u32>(offset, scroll::LE)?;
    if rva != 0 {
        rva += delta;
        data.pwrite_with::<u32>(rva, offset, scroll::LE)?;
    }
    Ok(rva)
}

fn fixup_rva_names(data: &mut [u8], offset: usize, delta: u32) -> error::Result<()>
{
    let mut offset = offset;
    loop {
        let mut ordinal = data.pread_with::<u32>(offset, scroll::LE)?;
        if ordinal == 0 { break; }

        if ordinal & IMAGE_ORDINAL_FLAG == 0 {
            ordinal += delta;
            data.pwrite_with::<u32>(ordinal, offset, scroll::LE)?;
        }
        offset += 4;
    }
    Ok(())
}

fn main() -> error::Result<()> {
    let path = "C:\\Projects\\wine2\\多线程\\dll.so\\ntdll.dll.so";
    let path = Path::new(path);
    let mut buffer = fs::read(path)?;
    let elf = Elf::parse(&buffer)?;
    let nt_addr = dlsym(&elf, "__wine_spec_nt_header").unwrap().st_value;
    // or nt->OptionalHeader.ImageBase(nt_bytes.pread_with(52, scroll::LE)?);
    let pe_addr = dlsym(&elf, "__wine_spec_pe_header").unwrap().st_value;
    let module = (pe_addr + 0xffff) & !0xffff;
    let module_offset = vm_to_offset(elf.program_headers.as_slice(), module).unwrap();
    let nt_offset = vm_to_offset(elf.program_headers.as_slice(), nt_addr).unwrap();
    // 获取原nt头
    let old_nt = buffer[nt_offset as usize..(nt_offset+SIZEOF_IMAGE_NT_HEADERS) as usize].to_vec();
    let pe_bytes = &mut buffer[module_offset as usize..];
    // const BUILTIN_SIGNATURE: &str = "Wine builtin DLL";
    let nt_file_offset: u64 = SIZEOF_IMAGE_DOS_HEADER + SIZEOF_BUILTIN_SIGNATURE;
    let sec_offset: u64 = nt_file_offset + SIZEOF_IMAGE_NT_HEADERS;
    // 构造 pe头
    pe_bytes.pwrite_with::<u16>(0x5a4d, 0,scroll::LE)?;
    pe_bytes.pwrite_with::<u32>(nt_file_offset as u32, 0x3c, scroll::LE)?;
    // pe_bytes.pwrite_with::<&str>(BUILTIN_SIGNATURE, 0x40, ());
    // 构造 nt头
    let mut cursor = Cursor::new(&mut pe_bytes[nt_file_offset as usize..]);
    cursor.write(&old_nt)?;
    let size: u32 = (SIZEOF_IMAGE_DOS_HEADER + SIZEOF_BUILTIN_SIGNATURE + SIZEOF_IMAGE_NT_HEADERS
        + 2 * SIZEOF_IMAGE_SECTION_HEADER) as u32;
    let nt_bytes = &mut pe_bytes[nt_file_offset as usize..];
    // read optional headers
    let section_alignment = nt_bytes.pread_with::<u32>(0x38, scroll::LE)?;
    let address_of_entry_point = nt_bytes.pread_with::<u32>(0x28, scroll::LE)?;
    let size_of_image = nt_bytes.pread_with::<u32>(0x50, scroll::LE)?;

    let delta: u32 = (nt_addr - module) as u32;
    let align_mask: u32 = section_alignment - 1;
    let code_start: u32 = (size + align_mask) & !align_mask;
    let data_start: u32 = delta & !align_mask;
    let code_end: u32 = data_start;
    let data_end: u32 = (size_of_image + delta + align_mask) & !align_mask;

    // fixup rva -> address_of_entry_point
    nt_bytes.pwrite_with::<u32>(address_of_entry_point - module as u32, 0x28, scroll::LE)?;
    // write data
    nt_bytes.pwrite_with::<u16>(2, 6, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(code_start, 0x2c, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(data_start, 0x30, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(code_end - code_start, 0x1c, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(data_end - data_start, 0x20, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(0, 0x24, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(data_end as u32, 0x50, scroll::LE)?;
    nt_bytes.pwrite_with::<u32>(module as u32, 0x34, scroll::LE)?;

    // write the code section
    let sec_bytes = &mut pe_bytes[sec_offset as usize..];
    sec_bytes.pwrite_with::<&str>(".text", 0, ())?;
    let sizeof_raw_data = code_end - code_start;
    sec_bytes.pwrite_with::<u32>(sizeof_raw_data, 8, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(code_start, 0xc, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(sizeof_raw_data, 0x10, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(code_start, 0x14, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, 0x24, scroll::LE)?;
    // write the data section
    let sec_bytes = &mut pe_bytes[(sec_offset + SIZEOF_IMAGE_SECTION_HEADER) as usize..];
    sec_bytes.pwrite_with::<&str>(".code", 0, ())?;
    let sizeof_raw_data = data_end - data_start;
    sec_bytes.pwrite_with::<u32>(sizeof_raw_data, 8, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(data_start, 0xc, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(sizeof_raw_data, 0x10, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(data_start, 0x14, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ, 0x24, scroll::LE)?;

    // 修复 rva
    let nt_bytes = &mut pe_bytes[nt_file_offset as usize..];
    let number_of_rva_and_sizes = nt_bytes.pread_with::<u32>(0x74, scroll::LE)?;
    for n in 0 .. number_of_rva_and_sizes {
        let offset: usize = (0x78 + n * 8) as usize;
        let mut rva = nt_bytes.pread_with::<u32>(offset, scroll::LE)?;
        if rva != 0 {
            rva += delta;
        }
        nt_bytes.pwrite_with::<u32>(rva, offset, scroll::LE)?;
    }
    // 处理导入表
    let nt_bytes = &pe_bytes[nt_file_offset as usize..];
    let import_addr = nt_bytes.pread_with::<u32>(0x80, scroll::LE)?;
    let import_size = nt_bytes.pread_with::<u32>(0x80 + 4, scroll::LE)?;
    let import_bytes = &mut pe_bytes[import_addr as usize..];
    if import_size > 0 {
        let mut offset = 0;
        loop {
            let name = fixup_rva_dwords(import_bytes, 0xc, delta)?;
            if name == 0 {
                break;
            }
            let original_first_thunk = fixup_rva_dwords(import_bytes, 0, delta)?;
            let first_thunk = fixup_rva_dwords(import_bytes, 0x10, delta)?;
            if original_first_thunk != 0 {
                fixup_rva_names(import_bytes, original_first_thunk as usize, delta)?;
            }
            if first_thunk != 0 {
                fixup_rva_names(import_bytes, first_thunk as usize, delta)?;
            }
            offset += 0x14;
        }
    }

    // 处理资源

    // 处理导出表
    let nt_bytes = &pe_bytes[nt_file_offset as usize..];
    let nt_bytes = &pe_bytes[nt_file_offset as usize..];
    let export_size = nt_bytes.pread_with::<u32>(0x78 + 0 * 8, scroll::LE)?;
    let export_addr = nt_bytes.pread_with::<u32>(0x78 + 0 * 8 + 4, scroll::LE)?;
    let export_bytes = &mut pe_bytes[import_addr as usize..];
    if export_size > 0 {
        fixup_rva_dwords(export_bytes, 0xc, delta)?;
        let address_of_functions = fixup_rva_dwords(export_bytes, 0x1c, delta)?;
        let address_of_names = fixup_rva_dwords(export_bytes, 0x20, delta)?;
        fixup_rva_dwords(export_bytes, 0x24, delta)?;

        let number_of_names = export_bytes.pread_with::<u32>(0x18, scroll::LE)?;
        let number_of_functions = export_bytes.pread_with::<u32>(0x14, scroll::LE)?;

        for n in 0 .. number_of_names {
            fixup_rva_dwords(export_bytes, (address_of_names + n * 4) as usize, delta)?;
        }

        for n in 0 .. number_of_functions {

            nt_bytes.pwrite_with::<u32>(address_of_entry_point - module as u32, 0x28, scroll::LE)?;
        }
    }

    let pe = PE::parse(&pe_bytes)?;
    let bytes = &pe_bytes;
    println!("{:?}", pe);
    println!("{:?}", pe.exports);
    println!("{:x} == {:x}", export_addr, export_size);

    // let sections = pe.sections;
    // if let Some(optional_header) = pe.header.optional_header {
    //     let file_alignment = optional_header.windows_fields.file_alignment;
    //     if let Some(export_table) = *optional_header.data_directories.get_export_table() {
    //         if let Ok(ed) =
    //         export::ExportData::parse(bytes, export_table, &sections, file_alignment)
    //         {
    //             println!("export data {:#?}", ed);
    //             println!("eee {:x}", ed.export_directory_table.address_table_entries);
    //             let exports = export::Export::parse(bytes, &ed, &sections, file_alignment)?;
    //             let name = ed.name;
    //             println!("name: {:#?}", exports);
    //             let export_data = Some(ed);
    //         }
    //     }
    // }
    Ok(())
}
