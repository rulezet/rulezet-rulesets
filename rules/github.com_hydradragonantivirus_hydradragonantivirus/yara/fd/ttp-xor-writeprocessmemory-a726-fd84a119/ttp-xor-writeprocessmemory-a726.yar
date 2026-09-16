rule TTP_XOR_WriteProcessMemory_a726 {
  strings:
    $key_a726 = { f0 54 [2] c2 76 [2] c4 43 [2] ea 43 [2] d5 5f }

  condition:
    any of them
}