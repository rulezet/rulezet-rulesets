rule TTP_XOR_WriteProcessMemory_a0e4 {
  strings:
    $key_a0e4 = { f7 96 [2] c5 b4 [2] c3 81 [2] ed 81 [2] d2 9d }

  condition:
    any of them
}