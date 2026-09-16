rule TTP_XOR_WriteProcessMemory_f5d4 {
  strings:
    $key_f5d4 = { a2 a6 [2] 90 84 [2] 96 b1 [2] b8 b1 [2] 87 ad }

  condition:
    any of them
}