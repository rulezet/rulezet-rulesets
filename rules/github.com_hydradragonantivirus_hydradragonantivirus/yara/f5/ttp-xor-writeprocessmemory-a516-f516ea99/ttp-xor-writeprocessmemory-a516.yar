rule TTP_XOR_WriteProcessMemory_a516 {
  strings:
    $key_a516 = { f2 64 [2] c0 46 [2] c6 73 [2] e8 73 [2] d7 6f }

  condition:
    any of them
}