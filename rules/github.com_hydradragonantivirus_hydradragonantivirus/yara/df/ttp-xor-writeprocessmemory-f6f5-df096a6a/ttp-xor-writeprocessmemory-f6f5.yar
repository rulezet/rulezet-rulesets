rule TTP_XOR_WriteProcessMemory_f6f5 {
  strings:
    $key_f6f5 = { a1 87 [2] 93 a5 [2] 95 90 [2] bb 90 [2] 84 8c }

  condition:
    any of them
}