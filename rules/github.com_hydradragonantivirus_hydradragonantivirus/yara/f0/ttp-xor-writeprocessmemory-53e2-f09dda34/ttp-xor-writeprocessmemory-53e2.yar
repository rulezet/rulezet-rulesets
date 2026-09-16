rule TTP_XOR_WriteProcessMemory_53e2 {
  strings:
    $key_53e2 = { 04 90 [2] 36 b2 [2] 30 87 [2] 1e 87 [2] 21 9b }

  condition:
    any of them
}