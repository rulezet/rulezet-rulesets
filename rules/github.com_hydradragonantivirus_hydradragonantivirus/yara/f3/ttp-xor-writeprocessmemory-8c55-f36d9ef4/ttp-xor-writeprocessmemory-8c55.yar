rule TTP_XOR_WriteProcessMemory_8c55 {
  strings:
    $key_8c55 = { db 27 [2] e9 05 [2] ef 30 [2] c1 30 [2] fe 2c }

  condition:
    any of them
}