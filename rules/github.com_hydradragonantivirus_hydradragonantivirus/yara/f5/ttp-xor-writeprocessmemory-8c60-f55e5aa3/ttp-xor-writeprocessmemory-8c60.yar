rule TTP_XOR_WriteProcessMemory_8c60 {
  strings:
    $key_8c60 = { db 12 [2] e9 30 [2] ef 05 [2] c1 05 [2] fe 19 }

  condition:
    any of them
}