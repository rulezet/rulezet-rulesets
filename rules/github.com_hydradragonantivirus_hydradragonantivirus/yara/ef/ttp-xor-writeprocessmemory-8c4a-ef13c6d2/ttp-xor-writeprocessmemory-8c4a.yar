rule TTP_XOR_WriteProcessMemory_8c4a {
  strings:
    $key_8c4a = { db 38 [2] e9 1a [2] ef 2f [2] c1 2f [2] fe 33 }

  condition:
    any of them
}