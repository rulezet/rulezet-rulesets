rule TTP_XOR_WriteProcessMemory_23a7 {
  strings:
    $key_23a7 = { 74 d5 [2] 46 f7 [2] 40 c2 [2] 6e c2 [2] 51 de }

  condition:
    any of them
}