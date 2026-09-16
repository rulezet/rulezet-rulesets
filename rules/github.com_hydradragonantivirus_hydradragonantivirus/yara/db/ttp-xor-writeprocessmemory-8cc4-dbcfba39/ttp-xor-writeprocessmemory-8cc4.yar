rule TTP_XOR_WriteProcessMemory_8cc4 {
  strings:
    $key_8cc4 = { db b6 [2] e9 94 [2] ef a1 [2] c1 a1 [2] fe bd }

  condition:
    any of them
}