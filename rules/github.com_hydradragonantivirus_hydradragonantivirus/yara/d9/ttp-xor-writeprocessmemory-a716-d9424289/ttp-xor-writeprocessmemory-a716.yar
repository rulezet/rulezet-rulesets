rule TTP_XOR_WriteProcessMemory_a716 {
  strings:
    $key_a716 = { f0 64 [2] c2 46 [2] c4 73 [2] ea 73 [2] d5 6f }

  condition:
    any of them
}