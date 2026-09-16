rule TTP_XOR_WriteProcessMemory_b126 {
  strings:
    $key_b126 = { e6 54 [2] d4 76 [2] d2 43 [2] fc 43 [2] c3 5f }

  condition:
    any of them
}