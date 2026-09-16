rule TTP_XOR_WriteProcessMemory_5966 {
  strings:
    $key_5966 = { 0e 14 [2] 3c 36 [2] 3a 03 [2] 14 03 [2] 2b 1f }

  condition:
    any of them
}