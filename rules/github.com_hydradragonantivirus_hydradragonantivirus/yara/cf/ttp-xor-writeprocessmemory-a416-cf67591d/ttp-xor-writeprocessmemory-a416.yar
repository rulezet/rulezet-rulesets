rule TTP_XOR_WriteProcessMemory_a416 {
  strings:
    $key_a416 = { f3 64 [2] c1 46 [2] c7 73 [2] e9 73 [2] d6 6f }

  condition:
    any of them
}