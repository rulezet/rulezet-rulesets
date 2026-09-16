rule TTP_XOR_WriteProcessMemory_f5e6 {
  strings:
    $key_f5e6 = { a2 94 [2] 90 b6 [2] 96 83 [2] b8 83 [2] 87 9f }

  condition:
    any of them
}