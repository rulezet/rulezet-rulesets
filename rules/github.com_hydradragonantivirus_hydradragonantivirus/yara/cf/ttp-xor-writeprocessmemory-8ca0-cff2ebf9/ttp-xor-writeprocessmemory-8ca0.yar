rule TTP_XOR_WriteProcessMemory_8ca0 {
  strings:
    $key_8ca0 = { db d2 [2] e9 f0 [2] ef c5 [2] c1 c5 [2] fe d9 }

  condition:
    any of them
}