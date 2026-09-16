rule TTP_XOR_WriteProcessMemory_b406 {
  strings:
    $key_b406 = { e3 74 [2] d1 56 [2] d7 63 [2] f9 63 [2] c6 7f }

  condition:
    any of them
}