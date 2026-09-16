rule TTP_XOR_WriteProcessMemory_b851 {
  strings:
    $key_b851 = { ef 23 [2] dd 01 [2] db 34 [2] f5 34 [2] ca 28 }

  condition:
    any of them
}