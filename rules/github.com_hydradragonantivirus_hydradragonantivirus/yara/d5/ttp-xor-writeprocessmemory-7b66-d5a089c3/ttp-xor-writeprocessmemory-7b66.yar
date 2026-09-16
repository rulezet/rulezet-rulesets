rule TTP_XOR_WriteProcessMemory_7b66 {
  strings:
    $key_7b66 = { 2c 14 [2] 1e 36 [2] 18 03 [2] 36 03 [2] 09 1f }

  condition:
    any of them
}