rule TTP_XOR_WriteProcessMemory_8cea {
  strings:
    $key_8cea = { db 98 [2] e9 ba [2] ef 8f [2] c1 8f [2] fe 93 }

  condition:
    any of them
}