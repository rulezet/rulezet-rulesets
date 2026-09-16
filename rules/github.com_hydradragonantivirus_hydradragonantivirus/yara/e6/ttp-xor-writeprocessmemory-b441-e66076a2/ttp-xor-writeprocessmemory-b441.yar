rule TTP_XOR_WriteProcessMemory_b441 {
  strings:
    $key_b441 = { e3 33 [2] d1 11 [2] d7 24 [2] f9 24 [2] c6 38 }

  condition:
    any of them
}