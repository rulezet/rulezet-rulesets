rule TTP_XOR_WriteProcessMemory_e7d9 {
  strings:
    $key_e7d9 = { b0 ab [2] 82 89 [2] 84 bc [2] aa bc [2] 95 a0 }

  condition:
    any of them
}