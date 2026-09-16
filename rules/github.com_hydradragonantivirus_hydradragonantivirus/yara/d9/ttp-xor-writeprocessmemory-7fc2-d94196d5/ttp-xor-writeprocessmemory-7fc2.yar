rule TTP_XOR_WriteProcessMemory_7fc2 {
  strings:
    $key_7fc2 = { 28 b0 [2] 1a 92 [2] 1c a7 [2] 32 a7 [2] 0d bb }

  condition:
    any of them
}