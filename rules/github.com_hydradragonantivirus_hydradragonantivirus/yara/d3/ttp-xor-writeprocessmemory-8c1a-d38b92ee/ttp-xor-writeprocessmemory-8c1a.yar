rule TTP_XOR_WriteProcessMemory_8c1a {
  strings:
    $key_8c1a = { db 68 [2] e9 4a [2] ef 7f [2] c1 7f [2] fe 63 }

  condition:
    any of them
}