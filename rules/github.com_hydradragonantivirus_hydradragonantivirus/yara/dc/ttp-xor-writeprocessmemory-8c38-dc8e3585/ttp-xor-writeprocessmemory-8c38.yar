rule TTP_XOR_WriteProcessMemory_8c38 {
  strings:
    $key_8c38 = { db 4a [2] e9 68 [2] ef 5d [2] c1 5d [2] fe 41 }

  condition:
    any of them
}