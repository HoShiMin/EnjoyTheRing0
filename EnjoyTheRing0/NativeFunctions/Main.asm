format MS COFF

@feat.00 = 1
public static @feat.00

;define x64 TRUE

include 'win32a.inc'

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

; Соглашение о вызове - fastcall (для MSVC и GCC):
; x64:
;  RCX  : 1й аргумент
;  RDX  : 2й аргумент
;  R8   : 3й аргумент
;  R9   : 4й аргумент
;  Стек : Аргументы в обратном порядке
;
; x32:
;  ECX  : 1й аргумент
;  EDX  : 2й аргумент
;  Стек : Аргументы в обратном порядке 

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  

; IO.inc:

if defined x64
  public StartBeeper
  public StopBeeper
  public SetBeeperRegime
  public SetBeeperOut
  public SetBeeperIn       
  public SetBeeperDivider   ; (Divider: Word)
  public SetBeeperFrequency ; (Frequency: PSingle);

  public WriteIoPortByte  ; (PortNumber: Word; Data: Byte)
  public WriteIoPortWord  ; (PortNumber: Word; Data: Word)
  public WriteIoPortDword ; (PortNumber: Word; Data: LongWord)

  public ReadIoPortByte  ; (PortNumber: Word): Byte
  public ReadIoPortWord  ; (PortNumber: Word): Word
  public ReadIoPortDword ; (PortNumber: Word): LongWord
else
  public StartBeeper        as '@StartBeeper@0'
  public StopBeeper         as '@StopBeeper@0'
  public SetBeeperRegime    as '@SetBeeperRegime@0'
  public SetBeeperOut       as '@SetBeeperOut@0'
  public SetBeeperIn        as '@SetBeeperIn@0'
  public SetBeeperDivider   as '@SetBeeperDivider@4'   ; (Divider: Word)
  public SetBeeperFrequency as '@SetBeeperFrequency@4' ; (Frequency: PSingle);

  public WriteIoPortByte  as '@WriteIoPortByte@8'  ; (PortNumber: Word; Data: Byte)
  public WriteIoPortWord  as '@WriteIoPortWord@8'  ; (PortNumber: Word; Data: Word)
  public WriteIoPortDword as '@WriteIoPortDword@8' ; (PortNumber: Word; Data: LongWord)

  public ReadIoPortByte  as '@ReadIoPortByte@4'  ; (PortNumber: Word): Byte
  public ReadIoPortWord  as '@ReadIoPortWord@4'  ; (PortNumber: Word): Word
  public ReadIoPortDword as '@ReadIoPortDword@4' ; (PortNumber: Word): LongWord
end if

; Interrupts.inc:

struct REGISTERS_STATE
  if defined x64
    RAX dq ?
    RCX dq ?
    RDX dq ?
  else
    EAX dw ?
    ECX dw ?
    EDX dw ?
  end if
ends ; *PREGISTERS_STATE

if defined x64
  public _CLI
  public _STI
  public _HLT
  public _INT ; (InterruptVector: Byte; RegistersState: PREGISTERS_STATE)
else
  public _CLI as '@_CLI@0'
  public _STI as '@_STI@0'
  public _HLT as '@_HLT@0'
  public _INT as '@_INT@0' ; (InterruptVector: Byte; RegistersState: PREGISTERS_STATE)
end if

; MSR.inc:

if defined x64
  public _RDPMC ; (Index: LongWord): UInt64
  public _RDMSR ; (Index: LongWord): UInt64
  public _WRMSR ; (Index: LongWord; Data: PUint64)
else
  public _RDPMC as '@_RDPMC@0' ; (Index: LongWord): UInt64
  public _RDMSR as '@_RDMSR@0' ; (Index: LongWord): UInt64
  public _WRMSR as '@_WRMSR@0' ; (Index: LongWord; Data: PUint64)
end if

; SystemRegisters.inc:

; Interrupt Descriptor Table (IDT) Register:
struct _IDTR
  Limit dw ?
  Base  dq ? ; PVOID
ends

; Global Descriptor Table (GDT) Register:
struct _GDTR
  Limit dw ?
  Base  dq ? ; PVOID
ends

; Task Register (TR):
struct _TR
  TSSDescriptorSegmentSelector dw ?
ends

if defined x64
  public DisableWriteProtection
  public EnableWriteProtection
  public IsSMEPPresent ; (VOID): Boolean
  public IsSMAPPresent ; (VOID): Boolean
  public DisableSMEP 
  public DisableSMAP 
  public EnableSMEP 
  public EnableSMAP
  public OperateCrDrRegister ; (OperationType: Word; OptionalData: LongWord|UInt64): LongWord|UInt64
  public IdtGdtTrOperation   ; (Operation: DWord; Data: Pointer);
else
  public DisableWriteProtection as '@DisableWriteProtection@0'
  public EnableWriteProtection  as '@EnableWriteProtection@0'
  public IsSMEPPresent as '@IsSMEPPresent@0' ; (VOID): Boolean
  public IsSMAPPresent as '@IsSMAPPresent@0' ; (VOID): Boolean
  public DisableSMEP as '@DisableSMEP@0'
  public DisableSMAP as '@DisableSMAP@0'
  public EnableSMEP  as '@EnableSMEP@0'
  public EnableSMAP  as '@EnableSMAP@0'
  public OperateCrDrRegister as '@OperateCrDrRegister@8' ; (OperationType: Word; OptionalData: LongWord|UInt64): LongWord|UInt64
  public IdtGdtTrOperation   as '@IdtGdtTrOperation@8'   ; (Operation: DWord; Data: Pointer);
end if

section '.code' code readable writeable executable

include 'IO.inc'              ; Порты ввода-вывода и пищалка  
include 'Interrupts.inc'      ; Прерывания, маскировка прерываний
include 'MSR.inc'             ; Модельно-специфичные регистры
include 'SystemRegisters.inc' ; Контрольные и отладочные регистры, WP, SMEP, SMAP