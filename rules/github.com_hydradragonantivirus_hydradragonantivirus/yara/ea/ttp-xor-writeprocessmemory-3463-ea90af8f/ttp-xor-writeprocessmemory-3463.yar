rule TTP_XOR_WriteProcessMemory_3463 {
  strings:
    $key_3463 = { 63 11 [2] 51 33 [2] 57 06 [2] 79 06 [2] 46 1a }

  condition:
    any of them
}