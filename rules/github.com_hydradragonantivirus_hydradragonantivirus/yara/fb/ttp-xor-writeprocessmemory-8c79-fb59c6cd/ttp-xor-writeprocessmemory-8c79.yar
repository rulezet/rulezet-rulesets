rule TTP_XOR_WriteProcessMemory_8c79 {
  strings:
    $key_8c79 = { db 0b [2] e9 29 [2] ef 1c [2] c1 1c [2] fe 00 }

  condition:
    any of them
}