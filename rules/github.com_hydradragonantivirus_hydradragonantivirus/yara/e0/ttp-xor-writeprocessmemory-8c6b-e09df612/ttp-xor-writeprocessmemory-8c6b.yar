rule TTP_XOR_WriteProcessMemory_8c6b {
  strings:
    $key_8c6b = { db 19 [2] e9 3b [2] ef 0e [2] c1 0e [2] fe 12 }

  condition:
    any of them
}