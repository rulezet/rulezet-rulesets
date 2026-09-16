rule TTP_XOR_WriteProcessMemory_8cc2 {
  strings:
    $key_8cc2 = { db b0 [2] e9 92 [2] ef a7 [2] c1 a7 [2] fe bb }

  condition:
    any of them
}