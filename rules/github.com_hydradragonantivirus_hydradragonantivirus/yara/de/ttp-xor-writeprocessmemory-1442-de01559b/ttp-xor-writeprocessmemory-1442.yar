rule TTP_XOR_WriteProcessMemory_1442 {
  strings:
    $key_1442 = { 43 30 [2] 71 12 [2] 77 27 [2] 59 27 [2] 66 3b }

  condition:
    any of them
}