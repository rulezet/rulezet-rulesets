rule TTP_XOR_WriteProcessMemory_b442 {
  strings:
    $key_b442 = { e3 30 [2] d1 12 [2] d7 27 [2] f9 27 [2] c6 3b }

  condition:
    any of them
}