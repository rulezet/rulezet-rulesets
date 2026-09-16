rule TTP_XOR_WriteProcessMemory_8c6d {
  strings:
    $key_8c6d = { db 1f [2] e9 3d [2] ef 08 [2] c1 08 [2] fe 14 }

  condition:
    any of them
}