rule TTP_XOR_WriteProcessMemory_15f0 {
  strings:
    $key_15f0 = { 42 82 [2] 70 a0 [2] 76 95 [2] 58 95 [2] 67 89 }

  condition:
    any of them
}