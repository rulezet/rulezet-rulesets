rule TTP_XOR_WriteProcessMemory_3763 {
  strings:
    $key_3763 = { 60 11 [2] 52 33 [2] 54 06 [2] 7a 06 [2] 45 1a }

  condition:
    any of them
}