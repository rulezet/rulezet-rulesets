rule TTP_XOR_WriteProcessMemory_8c72 {
  strings:
    $key_8c72 = { db 00 [2] e9 22 [2] ef 17 [2] c1 17 [2] fe 0b }

  condition:
    any of them
}