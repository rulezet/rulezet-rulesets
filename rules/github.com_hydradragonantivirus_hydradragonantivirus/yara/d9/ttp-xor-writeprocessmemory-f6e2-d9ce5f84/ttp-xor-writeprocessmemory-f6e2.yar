rule TTP_XOR_WriteProcessMemory_f6e2 {
  strings:
    $key_f6e2 = { a1 90 [2] 93 b2 [2] 95 87 [2] bb 87 [2] 84 9b }

  condition:
    any of them
}