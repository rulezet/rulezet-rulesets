rule TTP_XOR_WriteProcessMemory_f5d2 {
  strings:
    $key_f5d2 = { a2 a0 [2] 90 82 [2] 96 b7 [2] b8 b7 [2] 87 ab }

  condition:
    any of them
}