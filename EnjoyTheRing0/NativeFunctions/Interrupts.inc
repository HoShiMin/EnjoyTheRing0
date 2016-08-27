proc _CLI
  cli
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc _STI
  sti
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc _HLT
  hlt
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc _INT ; InterruptVector: Byte, RegistersState: PVOID
  
  if defined x64
    mov rdi, rdx
    push rdi
  else
    mov edi, edx
    push edi
  end if
  
  ; Записываем прерывание:
  mov ch, 0CDh
  xchg ch, cl
  mov word [InterruptBlock], cx
  
  ; Настраиваем регистры, если надо:
  if defined x64
    test rdx, rdx
    jz @Interrupt
    
    mov rax, qword [rdx]
    mov rcx, qword [rdx + 8]
    mov rdx, qword [rdx + 16]
  else
    test edx, edx
    jz @Interrupt
    
    mov eax, dword [edx]
    mov ecx, dword [edx + 4]
    mov edx, dword [edx + 8]
  end if

@Interrupt:
  InterruptBlock dw 9090h 
  
  if defined x64
    pop rdi
    test rdi, rdi
    jz @Exit
    mov qword [rdi     ], rax
    mov qword [rdi + 8 ], rcx
    mov qword [rdi + 16], rdx
  else
    pop edi
    test edi, edi
    jz @Exit
    mov dword [edi    ], eax
    mov dword [edi + 4], ecx
    mov dword [edi + 8], edx
  end if

@Exit:
  ret
endp