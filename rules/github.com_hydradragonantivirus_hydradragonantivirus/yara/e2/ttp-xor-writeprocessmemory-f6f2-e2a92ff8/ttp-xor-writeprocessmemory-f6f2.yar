rule TTP_XOR_WriteProcessMemory_f6f2 {
  strings:
    $key_f6f2 = { a1 80 [2] 93 a2 [2] 95 97 [2] bb 97 [2] 84 8b }

  condition:
    any of them
}