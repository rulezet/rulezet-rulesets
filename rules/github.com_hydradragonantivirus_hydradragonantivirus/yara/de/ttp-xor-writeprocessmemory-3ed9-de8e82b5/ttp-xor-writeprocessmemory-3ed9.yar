rule TTP_XOR_WriteProcessMemory_3ed9 {
  strings:
    $key_3ed9 = { 69 ab [2] 5b 89 [2] 5d bc [2] 73 bc [2] 4c a0 }

  condition:
    any of them
}