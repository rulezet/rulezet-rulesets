rule TTP_XOR_WriteProcessMemory_5ed9 {
  strings:
    $key_5ed9 = { 09 ab [2] 3b 89 [2] 3d bc [2] 13 bc [2] 2c a0 }

  condition:
    any of them
}