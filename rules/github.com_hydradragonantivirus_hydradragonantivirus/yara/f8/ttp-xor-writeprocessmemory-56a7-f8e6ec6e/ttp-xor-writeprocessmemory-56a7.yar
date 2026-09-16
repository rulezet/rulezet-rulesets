rule TTP_XOR_WriteProcessMemory_56a7 {
  strings:
    $key_56a7 = { 01 d5 [2] 33 f7 [2] 35 c2 [2] 1b c2 [2] 24 de }

  condition:
    any of them
}