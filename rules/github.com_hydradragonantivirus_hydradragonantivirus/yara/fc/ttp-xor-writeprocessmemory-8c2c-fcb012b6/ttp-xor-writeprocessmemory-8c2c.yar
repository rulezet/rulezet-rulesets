rule TTP_XOR_WriteProcessMemory_8c2c {
  strings:
    $key_8c2c = { db 5e [2] e9 7c [2] ef 49 [2] c1 49 [2] fe 55 }

  condition:
    any of them
}