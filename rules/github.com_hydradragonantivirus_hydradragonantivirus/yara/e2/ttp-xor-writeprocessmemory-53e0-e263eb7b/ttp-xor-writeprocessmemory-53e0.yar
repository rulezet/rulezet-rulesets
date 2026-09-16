rule TTP_XOR_WriteProcessMemory_53e0 {
  strings:
    $key_53e0 = { 04 92 [2] 36 b0 [2] 30 85 [2] 1e 85 [2] 21 99 }

  condition:
    any of them
}