rule TTP_XOR_WriteProcessMemory_af53 {
  strings:
    $key_af53 = { f8 21 [2] ca 03 [2] cc 36 [2] e2 36 [2] dd 2a }

  condition:
    any of them
}