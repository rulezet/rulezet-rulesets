rule TTP_XOR_WriteProcessMemory_f5e7 {
  strings:
    $key_f5e7 = { a2 95 [2] 90 b7 [2] 96 82 [2] b8 82 [2] 87 9e }

  condition:
    any of them
}