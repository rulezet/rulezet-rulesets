rule TTP_XOR_WriteProcessMemory_8cc6 {
  strings:
    $key_8cc6 = { db b4 [2] e9 96 [2] ef a3 [2] c1 a3 [2] fe bf }

  condition:
    any of them
}