rule TTP_XOR_WriteProcessMemory_8c1b {
  strings:
    $key_8c1b = { db 69 [2] e9 4b [2] ef 7e [2] c1 7e [2] fe 62 }

  condition:
    any of them
}