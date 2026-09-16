rule TTP_XOR_WriteProcessMemory_b850 {
  strings:
    $key_b850 = { ef 22 [2] dd 00 [2] db 35 [2] f5 35 [2] ca 29 }

  condition:
    any of them
}