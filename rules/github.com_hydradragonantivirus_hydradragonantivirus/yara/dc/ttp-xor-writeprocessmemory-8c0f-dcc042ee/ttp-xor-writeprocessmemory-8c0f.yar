rule TTP_XOR_WriteProcessMemory_8c0f {
  strings:
    $key_8c0f = { db 7d [2] e9 5f [2] ef 6a [2] c1 6a [2] fe 76 }

  condition:
    any of them
}