rule TTP_XOR_WriteProcessMemory_53e7 {
  strings:
    $key_53e7 = { 04 95 [2] 36 b7 [2] 30 82 [2] 1e 82 [2] 21 9e }

  condition:
    any of them
}