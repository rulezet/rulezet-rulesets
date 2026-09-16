rule TTP_XOR_WriteProcessMemory_3046 {
  strings:
    $key_3046 = { 67 34 [2] 55 16 [2] 53 23 [2] 7d 23 [2] 42 3f }

  condition:
    any of them
}