rule TTP_XOR_WriteProcessMemory_a616 {
  strings:
    $key_a616 = { f1 64 [2] c3 46 [2] c5 73 [2] eb 73 [2] d4 6f }

  condition:
    any of them
}