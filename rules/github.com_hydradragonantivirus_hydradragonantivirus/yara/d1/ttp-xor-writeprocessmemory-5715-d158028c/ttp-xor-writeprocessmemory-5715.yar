rule TTP_XOR_WriteProcessMemory_5715 {
  strings:
    $key_5715 = { 00 67 [2] 32 45 [2] 34 70 [2] 1a 70 [2] 25 6c }

  condition:
    any of them
}