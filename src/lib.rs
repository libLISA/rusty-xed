use std::sync::Mutex;
use xed_sys::{
    xed_decoded_inst_get_iclass, xed_decoded_inst_get_second_immediate,
    xed_decoded_inst_get_signed_immediate, xed_decoded_inst_get_unsigned_immediate,
    xed_decoded_inst_inst, xed_inst_iform_enum,
};

mod iclass;
mod iform;
mod operand_name;
mod reg;

pub use iclass::XedIClass;
pub use iform::XedIForm;
pub use operand_name::OperandName;
pub use reg::XedReg;

#[macro_export]
macro_rules! enum_impl {
    (enum $name:ident { $($original_name:ident => $new_name:ident),* $(,)* }) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($new_name,)*
        }

        impl $name {
            #[allow(non_upper_case_globals)]
            #[forbid(unused_variables)]
            pub fn from_u32(val: u32) -> Option<$name> {
                Some(match val {
                    $($original_name => $name::$new_name,)*
                    _ => return None,
                })
            }
        }
    };
}

static INITIALIZED: Mutex<bool> = Mutex::new(false);

#[derive(Clone)]
pub struct XedError(xed_sys::xed_error_enum_t);

impl std::fmt::Debug for XedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XedError")
            .field("code", &self.0)
            .field("message", &self.to_string())
            .finish()
    }
}

impl std::fmt::Display for XedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_message = unsafe {
            std::ffi::CStr::from_ptr(xed_sys::xed_error_enum_t2str(self.0)).to_string_lossy()
        };

        write!(f, "{error_message}")
    }
}

impl std::error::Error for XedError {}

#[non_exhaustive]
pub enum MachineMode {
    Long64,
}

impl MachineMode {
    fn to_xed(&self) -> u32 {
        match self {
            MachineMode::Long64 => xed_sys::XED_MACHINE_MODE_LONG_64,
        }
    }
}

#[non_exhaustive]
pub enum AddressWidth {
    Width64b,
}

impl AddressWidth {
    fn to_xed(&self) -> u32 {
        match self {
            AddressWidth::Width64b => xed_sys::XED_ADDRESS_WIDTH_64b,
        }
    }
}

pub struct Xed {
    mode: MachineMode,
    address_width: AddressWidth,
}

impl Xed {
    pub fn new(mode: MachineMode, address_width: AddressWidth) -> Self {
        {
            let mut lock = INITIALIZED.lock().unwrap();
            if !*lock {
                *lock = true;
                unsafe { xed_sys::xed_tables_init() }
            }
        }

        Self {
            mode,
            address_width,
        }
    }

    pub fn decode(&self, instr: &[u8]) -> Result<DecodedInstr, XedError> {
        let mut decoded = ::std::mem::MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
        unsafe {
            xed_sys::xed_decoded_inst_zero(decoded.as_mut_ptr());
            xed_sys::xed_decoded_inst_set_mode(
                decoded.as_mut_ptr(),
                self.mode.to_xed(),
                self.address_width.to_xed(),
            );

            let xed_error: xed_sys::xed_error_enum_t = xed_sys::xed_decode(
                decoded.as_mut_ptr(),
                instr.as_ptr(),
                instr.len().try_into().unwrap(),
            );
            if xed_error == xed_sys::XED_ERROR_NONE {
                let decoded = decoded.assume_init();
                Ok(DecodedInstr(decoded))
            } else {
                Err(XedError(xed_error))
            }
        }
    }
}

pub struct DecodedInstr(xed_sys::xed_decoded_inst_s);

impl DecodedInstr {
    pub fn operands(&self) -> Operands {
        Operands(self)
    }

    pub fn memory_accesses(&self) -> MemoryAccesses {
        MemoryAccesses(self)
    }

    pub fn iclass(&self) -> XedIClass {
        let iclass = unsafe { xed_decoded_inst_get_iclass(self.as_ptr()) };

        XedIClass::from_u32(iclass).unwrap()
    }

    pub fn iform(&self) -> XedIForm {
        let iform = unsafe {
            let inst = xed_sys::xed_decoded_inst_inst(self.as_ptr());
            xed_inst_iform_enum(inst)
        };

        XedIForm::from_u32(iform).unwrap()
    }

    fn as_ptr(&self) -> *const xed_sys::xed_decoded_inst_s {
        &self.0
    }

    fn as_inst(&self) -> *const xed_sys::xed_inst_s {
        unsafe { xed_decoded_inst_inst(self.as_ptr()) }
    }
}

pub struct Operands<'a>(&'a DecodedInstr);

impl<'a> Operands<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        unsafe { xed_sys::xed_decoded_inst_noperands(self.0.as_ptr()) }
            .try_into()
            .unwrap()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<Operand<'a>> {
        let index = index.try_into().unwrap();
        let operand = unsafe { xed_sys::xed_inst_operand(self.0.as_inst(), index) };

        Some(Operand {
            source: self.0,
            index,
            operand,
        })
    }
}

pub struct Operand<'a> {
    source: &'a DecodedInstr,
    index: u32,
    operand: *const xed_sys::xed_operand_t,
}

impl<'a> Operand<'a> {
    fn operand_name(&self) -> xed_sys::xed_operand_enum_t {
        unsafe { xed_sys::xed_operand_name(self.operand) }
    }

    pub fn name(&self) -> OperandName {
        OperandName::from_u32(self.operand_name()).unwrap()
    }

    pub fn operand_size_bits(&self) -> usize {
        unsafe {
            xed_sys::xed_decoded_inst_operand_length_bits(self.source.as_ptr(), self.index)
                .try_into()
                .unwrap()
        }
    }

    pub fn reg(&self) -> Option<XedReg> {
        if self.is_reg() {
            Some(unsafe {
                XedReg::from_u32(xed_sys::xed_decoded_inst_get_reg(
                    self.source.as_ptr(),
                    self.operand_name(),
                ))
                .unwrap()
            })
        } else {
            None
        }
    }

    pub fn is_reg(&self) -> bool {
        unsafe { xed_sys::xed_operand_is_register(self.operand_name()) != 0 }
    }

    pub fn is_imm(&self) -> bool {
        self.imm_value().is_some()
    }

    pub fn imm_value(&self) -> Option<u64> {
        Some(match self.name() {
            OperandName::Imm0 => unsafe {
                xed_decoded_inst_get_unsigned_immediate(self.source.as_ptr())
            },
            OperandName::Imm0Signed => unsafe {
                xed_decoded_inst_get_signed_immediate(self.source.as_ptr()) as u32 as u64
            },
            OperandName::Imm1 | OperandName::Imm1Bytes => unsafe {
                xed_decoded_inst_get_second_immediate(self.source.as_ptr()) as u64
            },
            _ => return None,
        })
    }

    pub fn is_memory_addressing_register(&self) -> bool {
        unsafe { xed_sys::xed_operand_is_memory_addressing_register(self.operand_name()) != 0 }
    }
}

pub struct MemoryAccesses<'a>(&'a DecodedInstr);

impl<'a> MemoryAccesses<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        unsafe { xed_sys::xed_decoded_inst_number_of_memory_operands(self.0.as_ptr()) }
            .try_into()
            .unwrap()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<MemoryAccess<'a>> {
        if index >= self.len() {
            None
        } else {
            Some(MemoryAccess {
                source: self.0,
                index: index.try_into().unwrap(),
            })
        }
    }
}

pub struct MemoryAccess<'a> {
    source: &'a DecodedInstr,
    index: u32,
}

impl std::fmt::Debug for MemoryAccess<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryAccess")
            .field("segment_reg", &self.segment_reg())
            .field("base_reg", &self.base_reg())
            .field("index_reg", &self.index_reg())
            .field("scale", &self.scale())
            .field("memory_displacement", &self.memory_displacement())
            .field(
                "memory_displacement_width",
                &self.memory_displacement_width(),
            )
            .field(
                "memory_displacement_width_bits",
                &self.memory_displacement_width_bits(),
            )
            .field("is_read", &self.is_read())
            .field("is_written", &self.is_written())
            .field("is_written_only", &self.is_written_only())
            .finish()
    }
}

impl MemoryAccess<'_> {
    fn return_reg(reg: u32) -> Option<XedReg> {
        if reg == xed_sys::XED_REG_INVALID {
            None
        } else {
            Some(XedReg::from_u32(reg).unwrap())
        }
    }

    pub fn segment_reg(&self) -> Option<XedReg> {
        unsafe {
            Self::return_reg(xed_sys::xed_decoded_inst_get_seg_reg(
                self.source.as_ptr(),
                self.index,
            ))
        }
    }

    pub fn base_reg(&self) -> Option<XedReg> {
        unsafe {
            Self::return_reg(xed_sys::xed_decoded_inst_get_base_reg(
                self.source.as_ptr(),
                self.index,
            ))
        }
    }

    pub fn scale(&self) -> u32 {
        unsafe { xed_sys::xed_decoded_inst_get_scale(self.source.as_ptr(), self.index) }
    }

    pub fn memory_displacement(&self) -> i64 {
        unsafe {
            xed_sys::xed_decoded_inst_get_memory_displacement(self.source.as_ptr(), self.index)
        }
    }

    pub fn memory_displacement_width(&self) -> u32 {
        unsafe {
            xed_sys::xed_decoded_inst_get_memory_displacement_width(
                self.source.as_ptr(),
                self.index,
            )
        }
    }

    pub fn memory_displacement_width_bits(&self) -> u32 {
        unsafe {
            xed_sys::xed_decoded_inst_get_memory_displacement_width_bits(
                self.source.as_ptr(),
                self.index,
            )
        }
    }

    pub fn is_read(&self) -> bool {
        unsafe { xed_sys::xed_decoded_inst_mem_read(self.source.as_ptr(), self.index) != 0 }
    }

    pub fn is_written(&self) -> bool {
        unsafe { xed_sys::xed_decoded_inst_mem_written(self.source.as_ptr(), self.index) != 0 }
    }

    pub fn is_written_only(&self) -> bool {
        unsafe { xed_sys::xed_decoded_inst_mem_written_only(self.source.as_ptr(), self.index) != 0 }
    }

    pub fn index_reg(&self) -> Option<XedReg> {
        unsafe {
            Self::return_reg(xed_sys::xed_decoded_inst_get_index_reg(
                self.source.as_ptr(),
                self.index,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{AddressWidth, MachineMode, Xed};

    #[test]
    pub fn imm_operands() {
        let xed = Xed::new(MachineMode::Long64, AddressWidth::Width64b);
        let instr = xed.decode(&[0x48, 0xC1, 0xE0, 0x03]).unwrap();
        let _op = instr.operands().get(1).unwrap();
    }
}
