rule TTP_XOR_WriteProcessMemory_5063 {
  strings:
    $key_5063 = { 07 11 [2] 35 33 [2] 33 06 [2] 1d 06 [2] 22 1a }

  condition:
    any of them
}