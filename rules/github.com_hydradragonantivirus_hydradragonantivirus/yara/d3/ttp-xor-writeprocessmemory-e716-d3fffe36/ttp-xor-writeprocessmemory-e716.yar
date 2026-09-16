rule TTP_XOR_WriteProcessMemory_e716 {
  strings:
    $key_e716 = { b0 64 [2] 82 46 [2] 84 73 [2] aa 73 [2] 95 6f }

  condition:
    any of them
}