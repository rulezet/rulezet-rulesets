rule TTP_XOR_WriteProcessMemory_f6f1 {
  strings:
    $key_f6f1 = { a1 83 [2] 93 a1 [2] 95 94 [2] bb 94 [2] 84 88 }

  condition:
    any of them
}