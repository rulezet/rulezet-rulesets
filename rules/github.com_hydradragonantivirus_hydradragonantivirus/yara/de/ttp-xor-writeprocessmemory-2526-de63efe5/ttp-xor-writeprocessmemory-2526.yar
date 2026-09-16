rule TTP_XOR_WriteProcessMemory_2526 {
  strings:
    $key_2526 = { 72 54 [2] 40 76 [2] 46 43 [2] 68 43 [2] 57 5f }

  condition:
    any of them
}