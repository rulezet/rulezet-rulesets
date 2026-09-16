rule TTP_XOR_WriteProcessMemory_8cf1 {
  strings:
    $key_8cf1 = { db 83 [2] e9 a1 [2] ef 94 [2] c1 94 [2] fe 88 }

  condition:
    any of them
}