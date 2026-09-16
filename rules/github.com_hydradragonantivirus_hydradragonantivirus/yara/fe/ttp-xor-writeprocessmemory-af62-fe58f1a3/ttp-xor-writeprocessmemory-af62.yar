rule TTP_XOR_WriteProcessMemory_af62 {
  strings:
    $key_af62 = { f8 10 [2] ca 32 [2] cc 07 [2] e2 07 [2] dd 1b }

  condition:
    any of them
}