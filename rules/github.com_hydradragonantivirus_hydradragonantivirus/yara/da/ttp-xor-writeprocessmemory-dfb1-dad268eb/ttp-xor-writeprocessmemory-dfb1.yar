rule TTP_XOR_WriteProcessMemory_dfb1 {
  strings:
    $key_dfb1 = { 88 c3 [2] ba e1 [2] bc d4 [2] 92 d4 [2] ad c8 }

  condition:
    any of them
}