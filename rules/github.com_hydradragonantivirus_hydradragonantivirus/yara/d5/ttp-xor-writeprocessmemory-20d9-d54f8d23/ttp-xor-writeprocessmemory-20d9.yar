rule TTP_XOR_WriteProcessMemory_20d9 {
  strings:
    $key_20d9 = { 77 ab [2] 45 89 [2] 43 bc [2] 6d bc [2] 52 a0 }

  condition:
    any of them
}