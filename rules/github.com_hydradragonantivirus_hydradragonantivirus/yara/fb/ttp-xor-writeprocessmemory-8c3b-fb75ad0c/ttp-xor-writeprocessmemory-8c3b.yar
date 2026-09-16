rule TTP_XOR_WriteProcessMemory_8c3b {
  strings:
    $key_8c3b = { db 49 [2] e9 6b [2] ef 5e [2] c1 5e [2] fe 42 }

  condition:
    any of them
}