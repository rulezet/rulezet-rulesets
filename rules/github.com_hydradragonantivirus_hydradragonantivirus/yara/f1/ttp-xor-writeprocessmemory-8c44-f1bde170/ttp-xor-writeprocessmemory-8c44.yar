rule TTP_XOR_WriteProcessMemory_8c44 {
  strings:
    $key_8c44 = { db 36 [2] e9 14 [2] ef 21 [2] c1 21 [2] fe 3d }

  condition:
    any of them
}