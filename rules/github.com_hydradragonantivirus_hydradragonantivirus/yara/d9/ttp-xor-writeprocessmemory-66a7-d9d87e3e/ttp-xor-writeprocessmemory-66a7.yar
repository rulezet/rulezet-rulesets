rule TTP_XOR_WriteProcessMemory_66a7 {
  strings:
    $key_66a7 = { 31 d5 [2] 03 f7 [2] 05 c2 [2] 2b c2 [2] 14 de }

  condition:
    any of them
}