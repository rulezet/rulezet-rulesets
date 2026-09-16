rule TTP_XOR_WriteProcessMemory_34a7 {
  strings:
    $key_34a7 = { 63 d5 [2] 51 f7 [2] 57 c2 [2] 79 c2 [2] 46 de }

  condition:
    any of them
}