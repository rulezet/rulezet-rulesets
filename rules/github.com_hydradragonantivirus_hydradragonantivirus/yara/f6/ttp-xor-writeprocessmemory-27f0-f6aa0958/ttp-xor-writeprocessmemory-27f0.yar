rule TTP_XOR_WriteProcessMemory_27f0 {
  strings:
    $key_27f0 = { 70 82 [2] 42 a0 [2] 44 95 [2] 6a 95 [2] 55 89 }

  condition:
    any of them
}