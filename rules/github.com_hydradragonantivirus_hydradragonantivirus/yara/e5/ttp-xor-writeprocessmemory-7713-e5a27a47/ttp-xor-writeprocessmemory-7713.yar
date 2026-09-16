rule TTP_XOR_WriteProcessMemory_7713 {
  strings:
    $key_7713 = { 20 61 [2] 12 43 [2] 14 76 [2] 3a 76 [2] 05 6a }

  condition:
    any of them
}