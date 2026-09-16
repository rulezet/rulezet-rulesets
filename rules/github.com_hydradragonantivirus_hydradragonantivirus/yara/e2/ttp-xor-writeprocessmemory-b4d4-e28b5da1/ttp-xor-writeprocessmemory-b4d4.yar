rule TTP_XOR_WriteProcessMemory_b4d4 {
  strings:
    $key_b4d4 = { e3 a6 [2] d1 84 [2] d7 b1 [2] f9 b1 [2] c6 ad }

  condition:
    any of them
}