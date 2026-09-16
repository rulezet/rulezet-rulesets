rule TTP_XOR_WriteProcessMemory_35a1 {
  strings:
    $key_35a1 = { 62 d3 [2] 50 f1 [2] 56 c4 [2] 78 c4 [2] 47 d8 }

  condition:
    any of them
}