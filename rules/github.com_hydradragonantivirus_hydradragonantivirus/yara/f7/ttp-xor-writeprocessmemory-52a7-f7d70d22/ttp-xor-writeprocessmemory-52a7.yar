rule TTP_XOR_WriteProcessMemory_52a7 {
  strings:
    $key_52a7 = { 05 d5 [2] 37 f7 [2] 31 c2 [2] 1f c2 [2] 20 de }

  condition:
    any of them
}