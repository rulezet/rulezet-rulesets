rule TTP_XOR_WriteProcessMemory_8c4f {
  strings:
    $key_8c4f = { db 3d [2] e9 1f [2] ef 2a [2] c1 2a [2] fe 36 }

  condition:
    any of them
}