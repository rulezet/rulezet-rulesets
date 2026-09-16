rule TTP_XOR_WriteProcessMemory_e7f0 {
  strings:
    $key_e7f0 = { b0 82 [2] 82 a0 [2] 84 95 [2] aa 95 [2] 95 89 }

  condition:
    any of them
}