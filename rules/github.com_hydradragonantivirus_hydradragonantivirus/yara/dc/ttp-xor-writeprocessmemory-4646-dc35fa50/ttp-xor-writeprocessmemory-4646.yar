rule TTP_XOR_WriteProcessMemory_4646 {
  strings:
    $key_4646 = { 11 34 [2] 23 16 [2] 25 23 [2] 0b 23 [2] 34 3f }

  condition:
    any of them
}