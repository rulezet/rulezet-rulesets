rule TTP_XOR_WriteProcessMemory_b4c0 {
  strings:
    $key_b4c0 = { e3 b2 [2] d1 90 [2] d7 a5 [2] f9 a5 [2] c6 b9 }

  condition:
    any of them
}