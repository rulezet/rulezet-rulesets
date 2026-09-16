rule TTP_XOR_WriteProcessMemory_af55 {
  strings:
    $key_af55 = { f8 27 [2] ca 05 [2] cc 30 [2] e2 30 [2] dd 2c }

  condition:
    any of them
}