rule TTP_XOR_WriteProcessMemory_8c1e {
  strings:
    $key_8c1e = { db 6c [2] e9 4e [2] ef 7b [2] c1 7b [2] fe 67 }

  condition:
    any of them
}