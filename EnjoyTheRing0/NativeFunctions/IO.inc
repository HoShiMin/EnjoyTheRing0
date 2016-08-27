proc StartBeeper
  ; Взводим первые два бита, отвечающие за включенность пищалки из порта 61h:
  in al, 61h
  or al, 00000011b
  out 61h, al
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc StopBeeper
  ; Сбрасываем первые два бита в порте 61h, отвечающие за включенность пищалки:
  in al, 61h
  and al, 11111100b
  out 61h, al
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc SetBeeperRegime
  ; Инициализируем пищалку:
  mov al, 10110110b ; 0B6h = 10 11 011 0
     ;     10 = номер канала, которым мы будем управлять (10b = второй канал)
     ;     11 = тип операции (11b = чтение/запись сначала младшего, а потом старшего байта)
     ;    011 = режим работы канала (011b = генератор прямоугольных импульсов (основной режим))
     ;      0 = формат счетчика (0 = 16-разрядное число от 0 до 0FFFFh)
  out 43h, al
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc SetBeeperOut
  ; Взводим 1й бит, отвечающий за положение мембраны из порта 61h - подаём напряжение:
  in al, 61h
  or al, 00000010b
  out 61h, al
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc SetBeeperIn
  ; Сбрасываем 1й бит, отвечающий за положение мембраны из порта 61h - снимаем напр¤жение:
  in al, 61h
  and al, 11111101b
  out 61h, al
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc SetBeeperDivider ; Divider: Word
  mov ax, cx
  out 42h, al
  shr ax, 8
  out 42h, al
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc SetBeeperFrequency ; Frequency: Word
  ; Divider = Round(1193182 / Frequency):
  
  mov ax, 19
  cmp cx, ax
  cmovl cx, ax
  
  movzx ecx, cx
  xor edx, edx
  mov eax, 1193182
  div ecx
  
  out 42h, al
  shr ax, 8
  out 42h, al
  
  ret
endp


;HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


proc WriteIoPortByte ; PortNumber: Word, InputData: Byte
  ; CX - номер порта
  ; DL - данные
  mov al, dl
  mov dx, cx
  out dx, al
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc WriteIoPortWord ; PortNumber: Word, InputData: Word
  ; CX - номер порта
  ; DX - данные
  mov ax, dx
  mov dx, cx
  out dx, ax
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc WriteIoPortDword ; PortNumber: Word, InputData: DWord
  ; CX - номер порта
  ; EDX - данные
  mov eax, edx
  mov dx, cx
  out dx, eax
  ret
endp


;HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


proc ReadIoPortByte ; PortNumber: Word 
  ; CX - номер порта
  ; AL - прочитанные данные
  mov dx, cx
  in al, dx
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc ReadIoPortWord ; PortNumber: Word
  ; CX - номер порта
  ; AX - прочитанные данные
  mov dx, cx
  in ax, dx
  ret
endp

;- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

proc ReadIoPortDword ; PortNumber: Word
  ; CX - номер порта
  ; EAX - прочитанные данные
  mov dx, cx
  in eax, dx
  ret
endp