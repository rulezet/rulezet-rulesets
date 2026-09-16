rule TTP_XOR_WriteProcessMemory_8cd1 {
  strings:
    $key_8cd1 = { db a3 [2] e9 81 [2] ef b4 [2] c1 b4 [2] fe a8 }

  condition:
    any of them
}