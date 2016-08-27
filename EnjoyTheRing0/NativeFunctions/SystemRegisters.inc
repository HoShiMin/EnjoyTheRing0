; Сбрасываем cr0.wp (16й бит, начиная с нулевого):
proc DisableWriteProtection
  if defined x64 
    mov rax, cr0
    btr rax, 16
    mov cr0, rax
  else
    mov eax, cr0
    btr eax, 16
    mov cr0, eax  
  end if
  
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; Взводим cr0.wp (16й бит, начиная с нулевого):
proc EnableWriteProtection
  if defined x64 
    mov rax, cr0
    bts rax, 16
    mov cr0, rax
  else
    mov eax, cr0
    bts eax, 16
    mov cr0, eax  
  end if
  
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; SMEP = 7й бит (начиная с нулевого) в EBX после CPUID (EAX = 7, ECX = 0):
proc IsSMEPPresent
  if defined x64
    push rbx
    push rcx
    push rdx
  else
    push ebx
    push ecx
    push edx
  end if
  
  mov eax, 7
  xor ecx, ecx
  cpuid
  xor eax, eax
  mov cx, 0FFFFh
  and ebx, 80h
  cmovnz ax, cx
  
  if defined x64
    pop rdx
    pop rcx
    pop rbx
  else
    pop edx
    pop ecx
    pop ebx
  end if
  
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; Сбрасываем cr4.smep (20й бит, начиная с нулевого):
proc DisableSMEP
  if defined x64 
    mov rax, cr4
    btr rax, 20
    mov cr4, rax
  else
    mov eax, cr4
    btr eax, 20
    mov cr4, eax  
  end if

  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; Взводим cr4.smep (20й бит, начиная с нулевого):
proc EnableSMEP
  if defined x64 
    mov rax, cr4
    bts rax, 20
    mov cr4, rax
  else
    mov eax, cr4
    bts eax, 20
    mov cr4, eax  
  end if

  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; SMAP = 20й бит (начиная с нулевого) в EBX после CPUID (EAX = 7, ECX = 0):
proc IsSMAPPresent
  if defined x64
    push rbx
    push rcx
    push rdx
  else
    push ebx
    push ecx
    push edx
  end if
  
  mov eax, 7
  xor ecx, ecx
  cpuid
  xor eax, eax
  mov cx, 0FFFFh
  and ebx, 100000h
  cmovnz ax, cx
  
  if defined x64
    pop rdx
    pop rcx
    pop rbx
  else
    pop edx
    pop ecx
    pop ebx
  end if
  
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; Сбрасываем cr4.smap (21й бит, начиная с нулевого):
proc DisableSMAP
  if defined x64 
    mov rax, cr4
    btr rax, 21
    mov cr4, rax
  else
    mov eax, cr4
    btr eax, 21
    mov cr4, eax  
  end if

  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

; Взводим cr4.smap (21й бит, начиная с нулевого):
proc EnableSMAP
  if defined x64 
    mov rax, cr4
    bts rax, 21
    mov cr4, rax
  else
    mov eax, cr4
    bts eax, 21
    mov cr4, eax  
  end if

  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc OperateCrDrRegister ; OperationType: Word, OptionalData: LongWord|Uint64
; CH  = NN - Номер действия [rCR:20h, wCR:22h, rDR:21h, wDR:23h]
; CL  = XX - Номер регистра [0..15]
; rDX = Опциональные данные для записи (если CH = 22h или 23h)
    
; XX - Номер регистра: [[C0, C8, D0, D8, E0, E8, F0, F8]]
; NN - Действие (r/w) и регистр (CR/DR) : [[rCR:20h, wCR:22h, rDR:21h, wDR:23h]]
    
;    0F NN XX | x86|x64 | mov rAX, xR0..xR7  | mov xR0..xR7 , rAX
; F0 0F NN C0 |     x86 | mov EAX, xR8..xR15 | mov xR8..xR15, EAX
; 44 0F NN XX |     x64 | mov RAX, xR8..xR15 | mov xR8..xR15, RAX

; Проверяем NN на валидность:
@ActionChecking:
  mov eax, 23212220h ; Перебираем все варианты: 20h, 22h, 21h и 23h
  cmp ch, al
  je @ValidationSuccessful
  shr eax, 8
  test eax, eax
  jz @ValidationFailed
  
@ValidationSuccessful:
  
  ; Проверяем на валидность номер регистра
  cmp cl, 15
  jg @ValidationFailed ; Если номер регистра > 15 - невалидный номер
  
  cmp cl, 7
  jg @NumberIsGreaterThan7 ; Если номер [8..15] - четырёхбайтовый машинный код

  ; Высчитываем байт, определяющий номер регистра:
  mov al, cl
  mov cl, 8 ; Байты, определяющие номер регистра, идут со смещением 8
  mul cl
  mov cl, al
  add cl, 0C0h ; CL = 0xC0 + ByteNumber * 8 - байт, определяющий номер регистра
  
  ; Путинская многоходовочка!
  mov ax, 900Fh ; В CH - номер операции, в AH - NOP
  xchg ah, ch   ; Поменяем их местами: в CH - NOP, в AH - номер операции
  
  ; AX = NN0Fh | AH = NN | AL = 0F |
  ; CX = 90XXh | CH = 90 | CL = XX |
                                      ; Lo Hi
  mov word [InstructionBlock + 0], ax ; 0F NN
  mov word [InstructionBlock + 2], cx ; XX 90
  jmp @ExecuteInstruction

@NumberIsGreaterThan7:
  if defined x64
    mov al, cl
    mov cl, 8 ; Байты, определяющие номер регистра, идут со смещением 8
    mul cl
    add al, 0C0h ; CH = 0xC0 + ByteNumber * 8 - байт, определяющий номер регистра
    mov cl, al
    xchg ah, al
    mov ax, 0F44h  
    
    ; AX = 0F44h | AH = 0F | AL = 44 |
    ; CX = XXNNh | CH = XX | CL = NN |
                                        ; Lo Hi
    mov word [InstructionBlock + 0], ax ; 44 0F
    mov word [InstructionBlock + 2], cx ; NN XX
  else
    xchg ch, cl
    shl cx, 16
    mov cx, 0FF0h ; ECX = XXNN0FF0h
    mov eax, ecx
    mov dword [InstructionBlock], eax ; F0 0F NN XX
  end if

@ExecuteInstruction:
  
  if defined x64 
    mov rax, rdx
  else
    mov eax, edx
  end if
  
  InstructionBlock db 4 dup 90h ; Резервируем место под инструкцию
  
@ValidationFailed:
  ret
  
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc IdtGdtTrOperation ; Operation: DWord, Data: Pointer
  mov dword [IdtGdtTrInstructionBlock], ecx
  IdtGdtTrInstructionBlock db 4 dup 90h
  ret
endp