rule TTP_XOR_WriteProcessMemory_b142 {
  strings:
    $key_b142 = { e6 30 [2] d4 12 [2] d2 27 [2] fc 27 [2] c3 3b }

  condition:
    any of them
}