rule TTP_XOR_WriteProcessMemory_b526 {
  strings:
    $key_b526 = { e2 54 [2] d0 76 [2] d6 43 [2] f8 43 [2] c7 5f }

  condition:
    any of them
}