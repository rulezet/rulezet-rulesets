rule TTP_XOR_WriteProcessMemory_b124 {
  strings:
    $key_b124 = { e6 56 [2] d4 74 [2] d2 41 [2] fc 41 [2] c3 5d }

  condition:
    any of them
}