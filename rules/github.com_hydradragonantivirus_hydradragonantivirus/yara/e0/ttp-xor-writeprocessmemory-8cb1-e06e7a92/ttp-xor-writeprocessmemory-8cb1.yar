rule TTP_XOR_WriteProcessMemory_8cb1 {
  strings:
    $key_8cb1 = { db c3 [2] e9 e1 [2] ef d4 [2] c1 d4 [2] fe c8 }

  condition:
    any of them
}