rule TTP_XOR_WriteProcessMemory_4642 {
  strings:
    $key_4642 = { 11 30 [2] 23 12 [2] 25 27 [2] 0b 27 [2] 34 3b }

  condition:
    any of them
}