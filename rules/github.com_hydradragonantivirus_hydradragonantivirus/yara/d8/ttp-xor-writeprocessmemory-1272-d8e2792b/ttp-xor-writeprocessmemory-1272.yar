rule TTP_XOR_WriteProcessMemory_1272 {
  strings:
    $key_1272 = { 45 00 [2] 77 22 [2] 71 17 [2] 5f 17 [2] 60 0b }

  condition:
    any of them
}