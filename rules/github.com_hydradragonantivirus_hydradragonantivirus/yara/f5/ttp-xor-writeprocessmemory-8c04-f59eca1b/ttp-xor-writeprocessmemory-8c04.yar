rule TTP_XOR_WriteProcessMemory_8c04 {
  strings:
    $key_8c04 = { db 76 [2] e9 54 [2] ef 61 [2] c1 61 [2] fe 7d }

  condition:
    any of them
}