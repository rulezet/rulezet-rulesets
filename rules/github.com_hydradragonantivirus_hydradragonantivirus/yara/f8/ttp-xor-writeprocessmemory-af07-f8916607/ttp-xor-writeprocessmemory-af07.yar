rule TTP_XOR_WriteProcessMemory_af07 {
  strings:
    $key_af07 = { f8 75 [2] ca 57 [2] cc 62 [2] e2 62 [2] dd 7e }

  condition:
    any of them
}