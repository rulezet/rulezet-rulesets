rule TTP_XOR_WriteProcessMemory_4de0 {
  strings:
    $key_4de0 = { 1a 92 [2] 28 b0 [2] 2e 85 [2] 00 85 [2] 3f 99 }

  condition:
    any of them
}