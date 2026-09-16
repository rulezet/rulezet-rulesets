rule TTP_XOR_WriteProcessMemory_8ca1 {
  strings:
    $key_8ca1 = { db d3 [2] e9 f1 [2] ef c4 [2] c1 c4 [2] fe d8 }

  condition:
    any of them
}