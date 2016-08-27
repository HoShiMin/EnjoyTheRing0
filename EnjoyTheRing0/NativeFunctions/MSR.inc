proc _RDPMC ; Index: DWORD
  rdpmc
  
  if defined x64
    mov rcx, 0FFFFFFFFh
    and rax, rcx ; Зануляем старшую часть RAX
    shl rdx, 32
    or rax, rdx
  end if

  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc _RDMSR ; Index: DWORD
  rdmsr

  if defined x64
    mov rcx, 0FFFFFFFFh
    and rax, rcx ; Зануляем старшую часть RAX
    shl rdx, 32
    or rax, rdx
  end if 
  
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc _WRMSR ; Index: DWORD, Value: PQWORD
  if defined x64
    mov eax, dword [rdx]
    mov edx, dword [rdx + 4]  
  else
    mov eax, dword [edx]
    mov edx, dword [edx + 4]   
  end if 

  wrmsr 
   
  ret
endp