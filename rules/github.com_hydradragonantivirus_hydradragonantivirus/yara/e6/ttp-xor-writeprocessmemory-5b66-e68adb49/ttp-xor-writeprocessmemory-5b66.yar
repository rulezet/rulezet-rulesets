rule TTP_XOR_WriteProcessMemory_5b66 {
  strings:
    $key_5b66 = { 0c 14 [2] 3e 36 [2] 38 03 [2] 16 03 [2] 29 1f }

  condition:
    any of them
}