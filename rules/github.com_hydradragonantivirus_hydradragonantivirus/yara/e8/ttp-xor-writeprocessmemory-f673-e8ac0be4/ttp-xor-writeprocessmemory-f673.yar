rule TTP_XOR_WriteProcessMemory_f673 {
  strings:
    $key_f673 = { a1 01 [2] 93 23 [2] 95 16 [2] bb 16 [2] 84 0a }

  condition:
    any of them
}