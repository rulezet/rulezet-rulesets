rule TTP_XOR_WriteProcessMemory_f6d4 {
  strings:
    $key_f6d4 = { a1 a6 [2] 93 84 [2] 95 b1 [2] bb b1 [2] 84 ad }

  condition:
    any of them
}