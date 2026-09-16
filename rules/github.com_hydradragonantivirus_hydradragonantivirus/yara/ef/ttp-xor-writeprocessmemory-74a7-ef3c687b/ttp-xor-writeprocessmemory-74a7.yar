rule TTP_XOR_WriteProcessMemory_74a7 {
  strings:
    $key_74a7 = { 23 d5 [2] 11 f7 [2] 17 c2 [2] 39 c2 [2] 06 de }

  condition:
    any of them
}