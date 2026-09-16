rule TTP_XOR_WriteProcessMemory_46f0 {
  strings:
    $key_46f0 = { 11 82 [2] 23 a0 [2] 25 95 [2] 0b 95 [2] 34 89 }

  condition:
    any of them
}