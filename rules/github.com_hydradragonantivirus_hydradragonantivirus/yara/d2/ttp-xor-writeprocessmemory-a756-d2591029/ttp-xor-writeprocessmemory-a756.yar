rule TTP_XOR_WriteProcessMemory_a756 {
  strings:
    $key_a756 = { f0 24 [2] c2 06 [2] c4 33 [2] ea 33 [2] d5 2f }

  condition:
    any of them
}