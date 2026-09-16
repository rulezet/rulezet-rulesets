rule TTP_XOR_WriteProcessMemory_e7a6 {
  strings:
    $key_e7a6 = { b0 d4 [2] 82 f6 [2] 84 c3 [2] aa c3 [2] 95 df }

  condition:
    any of them
}