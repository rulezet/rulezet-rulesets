rule TTP_XOR_WriteProcessMemory_33a1 {
  strings:
    $key_33a1 = { 64 d3 [2] 56 f1 [2] 50 c4 [2] 7e c4 [2] 41 d8 }

  condition:
    any of them
}