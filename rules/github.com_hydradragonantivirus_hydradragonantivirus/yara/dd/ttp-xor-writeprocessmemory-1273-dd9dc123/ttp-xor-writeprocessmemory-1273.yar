rule TTP_XOR_WriteProcessMemory_1273 {
  strings:
    $key_1273 = { 45 01 [2] 77 23 [2] 71 16 [2] 5f 16 [2] 60 0a }

  condition:
    any of them
}