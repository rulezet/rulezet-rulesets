rule TTP_XOR_WriteProcessMemory_8c4e {
  strings:
    $key_8c4e = { db 3c [2] e9 1e [2] ef 2b [2] c1 2b [2] fe 37 }

  condition:
    any of them
}