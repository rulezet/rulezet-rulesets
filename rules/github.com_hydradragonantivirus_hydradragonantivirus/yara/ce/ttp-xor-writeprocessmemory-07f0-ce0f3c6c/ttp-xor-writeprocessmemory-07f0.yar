rule TTP_XOR_WriteProcessMemory_07f0 {
  strings:
    $key_07f0 = { 50 82 [2] 62 a0 [2] 64 95 [2] 4a 95 [2] 75 89 }

  condition:
    any of them
}