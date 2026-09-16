rule TTP_XOR_WriteProcessMemory_64a1 {
  strings:
    $key_64a1 = { 33 d3 [2] 01 f1 [2] 07 c4 [2] 29 c4 [2] 16 d8 }

  condition:
    any of them
}