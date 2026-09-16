rule TTP_XOR_WriteProcessMemory_b566 {
  strings:
    $key_b566 = { e2 14 [2] d0 36 [2] d6 03 [2] f8 03 [2] c7 1f }

  condition:
    any of them
}