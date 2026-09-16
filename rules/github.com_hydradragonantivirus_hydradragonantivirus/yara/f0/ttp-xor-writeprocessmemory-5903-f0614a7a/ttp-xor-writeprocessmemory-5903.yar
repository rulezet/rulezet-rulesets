rule TTP_XOR_WriteProcessMemory_5903 {
  strings:
    $key_5903 = { 0e 71 [2] 3c 53 [2] 3a 66 [2] 14 66 [2] 2b 7a }

  condition:
    any of them
}