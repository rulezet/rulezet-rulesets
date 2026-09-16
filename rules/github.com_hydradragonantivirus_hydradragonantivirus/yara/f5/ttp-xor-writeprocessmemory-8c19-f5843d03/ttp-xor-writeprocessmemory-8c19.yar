rule TTP_XOR_WriteProcessMemory_8c19 {
  strings:
    $key_8c19 = { db 6b [2] e9 49 [2] ef 7c [2] c1 7c [2] fe 60 }

  condition:
    any of them
}