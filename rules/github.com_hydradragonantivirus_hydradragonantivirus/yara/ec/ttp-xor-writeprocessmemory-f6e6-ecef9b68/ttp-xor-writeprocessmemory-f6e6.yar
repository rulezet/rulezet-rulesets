rule TTP_XOR_WriteProcessMemory_f6e6 {
  strings:
    $key_f6e6 = { a1 94 [2] 93 b6 [2] 95 83 [2] bb 83 [2] 84 9f }

  condition:
    any of them
}