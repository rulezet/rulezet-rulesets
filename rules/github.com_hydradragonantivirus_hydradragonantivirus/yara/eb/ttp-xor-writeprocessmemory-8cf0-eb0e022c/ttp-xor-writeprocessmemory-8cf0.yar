rule TTP_XOR_WriteProcessMemory_8cf0 {
  strings:
    $key_8cf0 = { db 82 [2] e9 a0 [2] ef 95 [2] c1 95 [2] fe 89 }

  condition:
    any of them
}