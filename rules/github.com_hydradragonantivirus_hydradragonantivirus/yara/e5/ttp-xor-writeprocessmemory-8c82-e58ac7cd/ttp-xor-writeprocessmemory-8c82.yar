rule TTP_XOR_WriteProcessMemory_8c82 {
  strings:
    $key_8c82 = { db f0 [2] e9 d2 [2] ef e7 [2] c1 e7 [2] fe fb }

  condition:
    any of them
}