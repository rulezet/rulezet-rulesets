rule TTP_XOR_WriteProcessMemory_07a1 {
  strings:
    $key_07a1 = { 50 d3 [2] 62 f1 [2] 64 c4 [2] 4a c4 [2] 75 d8 }

  condition:
    any of them
}