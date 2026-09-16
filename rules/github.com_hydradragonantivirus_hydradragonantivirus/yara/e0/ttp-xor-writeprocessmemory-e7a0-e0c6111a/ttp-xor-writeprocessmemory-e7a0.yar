rule TTP_XOR_WriteProcessMemory_e7a0 {
  strings:
    $key_e7a0 = { b0 d2 [2] 82 f0 [2] 84 c5 [2] aa c5 [2] 95 d9 }

  condition:
    any of them
}