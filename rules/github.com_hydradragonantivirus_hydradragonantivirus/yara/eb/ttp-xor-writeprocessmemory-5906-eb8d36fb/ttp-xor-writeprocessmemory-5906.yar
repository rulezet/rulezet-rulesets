rule TTP_XOR_WriteProcessMemory_5906 {
  strings:
    $key_5906 = { 0e 74 [2] 3c 56 [2] 3a 63 [2] 14 63 [2] 2b 7f }

  condition:
    any of them
}