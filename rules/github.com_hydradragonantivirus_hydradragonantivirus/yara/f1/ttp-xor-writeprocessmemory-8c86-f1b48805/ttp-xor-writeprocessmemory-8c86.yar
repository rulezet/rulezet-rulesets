rule TTP_XOR_WriteProcessMemory_8c86 {
  strings:
    $key_8c86 = { db f4 [2] e9 d6 [2] ef e3 [2] c1 e3 [2] fe ff }

  condition:
    any of them
}