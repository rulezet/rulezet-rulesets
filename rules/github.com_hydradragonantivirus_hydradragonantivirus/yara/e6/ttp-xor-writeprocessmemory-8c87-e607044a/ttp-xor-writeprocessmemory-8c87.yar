rule TTP_XOR_WriteProcessMemory_8c87 {
  strings:
    $key_8c87 = { db f5 [2] e9 d7 [2] ef e2 [2] c1 e2 [2] fe fe }

  condition:
    any of them
}