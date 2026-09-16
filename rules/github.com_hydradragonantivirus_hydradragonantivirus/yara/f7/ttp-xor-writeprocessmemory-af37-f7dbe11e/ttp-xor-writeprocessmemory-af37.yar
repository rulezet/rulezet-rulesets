rule TTP_XOR_WriteProcessMemory_af37 {
  strings:
    $key_af37 = { f8 45 [2] ca 67 [2] cc 52 [2] e2 52 [2] dd 4e }

  condition:
    any of them
}