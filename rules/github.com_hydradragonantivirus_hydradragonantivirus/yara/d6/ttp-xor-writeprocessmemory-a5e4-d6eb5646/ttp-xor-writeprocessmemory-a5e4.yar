rule TTP_XOR_WriteProcessMemory_a5e4 {
  strings:
    $key_a5e4 = { f2 96 [2] c0 b4 [2] c6 81 [2] e8 81 [2] d7 9d }

  condition:
    any of them
}