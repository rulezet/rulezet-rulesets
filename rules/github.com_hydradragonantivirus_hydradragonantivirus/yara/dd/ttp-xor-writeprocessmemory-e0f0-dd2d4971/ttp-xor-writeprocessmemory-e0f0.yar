rule TTP_XOR_WriteProcessMemory_e0f0 {
  strings:
    $key_e0f0 = { b7 82 [2] 85 a0 [2] 83 95 [2] ad 95 [2] 92 89 }

  condition:
    any of them
}