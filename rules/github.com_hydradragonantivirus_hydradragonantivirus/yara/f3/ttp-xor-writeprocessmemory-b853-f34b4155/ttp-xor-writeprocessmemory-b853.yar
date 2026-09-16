rule TTP_XOR_WriteProcessMemory_b853 {
  strings:
    $key_b853 = { ef 21 [2] dd 03 [2] db 36 [2] f5 36 [2] ca 2a }

  condition:
    any of them
}