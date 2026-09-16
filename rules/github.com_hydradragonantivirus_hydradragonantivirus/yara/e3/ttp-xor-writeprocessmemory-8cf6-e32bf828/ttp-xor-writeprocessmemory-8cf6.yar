rule TTP_XOR_WriteProcessMemory_8cf6 {
  strings:
    $key_8cf6 = { db 84 [2] e9 a6 [2] ef 93 [2] c1 93 [2] fe 8f }

  condition:
    any of them
}