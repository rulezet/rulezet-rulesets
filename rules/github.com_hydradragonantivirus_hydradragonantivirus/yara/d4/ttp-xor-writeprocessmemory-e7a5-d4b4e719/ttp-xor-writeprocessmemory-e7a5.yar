rule TTP_XOR_WriteProcessMemory_e7a5 {
  strings:
    $key_e7a5 = { b0 d7 [2] 82 f5 [2] 84 c0 [2] aa c0 [2] 95 dc }

  condition:
    any of them
}