rule TTP_XOR_WriteProcessMemory_5662 {
  strings:
    $key_5662 = { 01 10 [2] 33 32 [2] 35 07 [2] 1b 07 [2] 24 1b }

  condition:
    any of them
}