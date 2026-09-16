rule TTP_XOR_WriteProcessMemory_b862 {
  strings:
    $key_b862 = { ef 10 [2] dd 32 [2] db 07 [2] f5 07 [2] ca 1b }

  condition:
    any of them
}