rule TTP_XOR_WriteProcessMemory_8c65 {
  strings:
    $key_8c65 = { db 17 [2] e9 35 [2] ef 00 [2] c1 00 [2] fe 1c }

  condition:
    any of them
}