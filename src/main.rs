use std::path::Path;
use std::fs;
use goblin::error;
use goblin::elf::{Elf, Sym};
use goblin::elf::program_header::ProgramHeader;
use goblin::pe::PE;
use scroll::{Pread, Pwrite};
use std::io::{Cursor, Write};
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_WRITE};
use std::collections::HashMap;

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
                // println!("n is {}, type is ", n, )
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

fn fixup_rva_dwords(data: &mut [u8], offset: usize, delta: i32) -> error::Result<u32>
{
    let mut rva = data.pread_with::<u32>(offset, scroll::LE)?;
    if rva != 0 {
        rva = (rva as i32 + delta) as u32;
        data.pwrite_with::<u32>(rva, offset, scroll::LE)?;
    }
    Ok(rva)
}

#[allow(dead_code)]
fn fixup_rva_names(data: &mut [u8], offset: usize, delta: i32) -> error::Result<()>
{
    let mut offset = offset;
    loop {
        let mut ordinal = data.pread_with::<u32>(offset, scroll::LE)?;
        if ordinal == 0 { break; }

        if ordinal & IMAGE_ORDINAL_FLAG == 0 {
            ordinal += delta as u32;
            data.pwrite_with::<u32>(ordinal, offset, scroll::LE)?;
        }
        offset += 4;
    }
    Ok(())
}

fn main() -> error::Result<()> {
    let module_name = "kernel32.dll";
    let path = "C:\\Projects\\wine2\\多线程\\dll.so\\kernel32.dll.so";
    let path = Path::new(path);
    let mut buffer = fs::read(path)?;
    let elf = Elf::parse(&buffer)?;
    let nt_addr = dlsym(&elf, "__wine_spec_nt_header").unwrap().st_value;
    // or nt->OptionalHeader.ImageBase(nt_bytes.pread_with(52, scroll::LE)?);
    let pe_addr = dlsym(&elf, "__wine_spec_pe_header").unwrap().st_value;
    let module = (pe_addr + 0xffff) & !0xffff;
    let phdrs = elf.program_headers.to_vec();
    println!("header is {} === {}", elf.header.e_phoff as usize, elf.header.e_phnum as usize);
    println!("phdr len is {}", phdrs.len());
    let module_offset = vm_to_offset(&phdrs, module).unwrap();
    let nt_offset = vm_to_offset(&phdrs, nt_addr).unwrap();
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
    // 载入后的地址偏移
    let delta: i32 = (nt_addr - module) as i32;
    let align_mask: u32 = section_alignment - 1;
    let code_start: u32 = (size + align_mask) & !align_mask;
    let data_start: u32 = delta as u32 & !align_mask;
    let code_end: u32 = data_start;
    let data_end: u32 = ((size_of_image as i32 + delta) as u32 + align_mask) & !align_mask;

    // println!("<{:x} == {:x}>, <{:x} == {:x}>", code_start, code_end, data_start, data_end);
    // fixup rva -> address_of_entry_point
    nt_bytes.pwrite_with::<u32>(address_of_entry_point - module as u32, 0x28, scroll::LE)?;
    let rva_to_offset = |rva: u64| -> u64 {
        vm_to_offset(&phdrs, rva + module).unwrap() - module_offset
    };
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
    // 处理重定位
    sec_bytes.pwrite_with::<u32>(rva_to_offset(data_start as u64) as u32, 0x14, scroll::LE)?;
    sec_bytes.pwrite_with::<u32>(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ, 0x24, scroll::LE)?;

    // 修复 rva
    let nt_bytes = &mut pe_bytes[nt_file_offset as usize..];
    let number_of_rva_and_sizes = nt_bytes.pread_with::<u32>(0x74, scroll::LE)?;
    for n in 0 .. number_of_rva_and_sizes {
        let offset: usize = (0x78 + n * 8) as usize;
        fixup_rva_dwords(nt_bytes, offset, delta)?;
    }

    // 抹掉导入表
    nt_bytes.pwrite_with::<u64>(0, 0x80, scroll::LE)?;

    // 处理导入表
    // let nt_bytes = &pe_bytes[nt_file_offset as usize..];
    // let import_addr = nt_bytes.pread_with::<u32>(0x80, scroll::LE)?;
    // let import_addr = rva_to_offset((import_addr) as u64) ;
    // let import_size = nt_bytes.pread_with::<u32>(0x80 + 4, scroll::LE)?;
    // let import_bytes = &mut pe_bytes[import_addr as usize..];
    // if import_size > 0 {
    //     let mut offset = 0;
    //     loop {
    //         let name = fixup_rva_dwords(import_bytes, 0xc, delta)?;
    //         if name == 0 {
    //             break;
    //         }
    //         let original_first_thunk = fixup_rva_dwords(import_bytes, 0, delta)?;
    //         // let original_first_thunk: u32 = (rva_to_offset(original_first_thunk as u64) - import_addr) as u32;
    //         let first_thunk = fixup_rva_dwords(import_bytes, 0x10, delta)?;
    //         if original_first_thunk != 0 {
    //             fixup_rva_names(import_bytes, original_first_thunk as usize, delta)?;
    //         }
    //         if first_thunk != 0 {
    //             fixup_rva_names(import_bytes, first_thunk as usize, delta)?;
    //         }
    //         offset += 0x14;
    //     }
    // }

    // 处理资源

    // 处理导出表
    let nt_bytes = &pe_bytes[nt_file_offset as usize..];
    let export_size = nt_bytes.pread_with::<u32>(0x78 + 4, scroll::LE)?;
    let export_addr = nt_bytes.pread_with::<u32>(0x78, scroll::LE)?;
    let export_addr = rva_to_offset((export_addr) as u64) ;
    let export_bytes = &mut pe_bytes[export_addr as usize..];
    if export_size > 0 {
        fixup_rva_dwords(export_bytes, 0xc, delta)?;
        let address_of_functions = fixup_rva_dwords(export_bytes, 0x1c, delta)?;
        let address_of_functions: u32 = (rva_to_offset(address_of_functions as u64) - export_addr) as u32;
        let address_of_names = fixup_rva_dwords(export_bytes, 0x20, delta)?;
        let address_of_names: u32 = (rva_to_offset(address_of_names as u64) - export_addr) as u32;
        fixup_rva_dwords(export_bytes, 0x24, delta)?;
        let number_of_functions = export_bytes.pread_with::<u32>(0x14, scroll::LE)?;
        let number_of_names = export_bytes.pread_with::<u32>(0x18, scroll::LE)?;

        for n in 0 .. number_of_names {
            let _name_addr = fixup_rva_dwords(export_bytes, (address_of_names + n * 4) as usize, delta)?;
            // let name_addr = rva_to_offset(name_addr as u64);
            // let name:&str = export_bytes.pread((name_addr - export_addr) as usize).unwrap();
            // println!("{}", name);
        }
        for n in 0 .. number_of_functions {
            let func_addr = export_bytes.pread_with::<u32>((address_of_functions + n * 4) as usize,  scroll::LE)?;
            export_bytes.pwrite_with::<u32>(func_addr - module as u32, (address_of_functions + n * 4) as usize,  scroll::LE)?;
        }
    }
    let pe = PE::parse(&pe_bytes)?;
    let exports = pe.exports;
    // 加载toml
    let spec_file = "C:\\Projects\\wine2\\多线程\\dll.so\\spec.toml";
    let spec = fs::read_to_string(spec_file)?;
    let spec: HashMap<String, HashMap<String, u32>> = toml::from_str(&spec).unwrap();
    for export in  exports {
        if export.name.unwrap().starts_with("__imp__") {
            println!("found is {:#?}", export);
        }
        if export.reexport.is_some() {
            continue;
        }
        let name = export.name.unwrap();
        let data = &pe_bytes[export.offset - 10..];
        if let Some(df) = spec.get(module_name).unwrap().get(name) {
            // stub
            if (*df & 0x1000000) != 0 {
                continue;
            }
            if *df != 0x63 {
                println!("{:?} ==> {:x?} ==> {:x}", name, data[0..10].to_vec(), df);

                if data[0..10].iter().cloned().ne(vec![0x90; 10]) {
                    println!("{:#?}, is wrong!", export.reexport);
                } else {

                }
            }
        } else {
            println!("{:?} ==> {:?} NOT FOUND", name, data[0..10].to_vec());
        }
    }
    Ok(())
}