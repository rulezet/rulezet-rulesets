rule TTP_XOR_WriteProcessMemory_fca1 {
  strings:
    $key_fca1 = { ab d3 [2] 99 f1 [2] 9f c4 [2] b1 c4 [2] 8e d8 }

  condition:
    any of them
}