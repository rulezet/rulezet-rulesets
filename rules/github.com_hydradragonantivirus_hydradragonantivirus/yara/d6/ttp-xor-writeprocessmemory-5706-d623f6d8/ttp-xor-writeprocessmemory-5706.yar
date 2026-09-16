rule TTP_XOR_WriteProcessMemory_5706 {
  strings:
    $key_5706 = { 00 74 [2] 32 56 [2] 34 63 [2] 1a 63 [2] 25 7f }

  condition:
    any of them
}