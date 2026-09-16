rule TTP_XOR_WriteProcessMemory_72a1 {
  strings:
    $key_72a1 = { 25 d3 [2] 17 f1 [2] 11 c4 [2] 3f c4 [2] 00 d8 }

  condition:
    any of them
}