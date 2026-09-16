rule TTP_XOR_WriteProcessMemory_5562 {
  strings:
    $key_5562 = { 02 10 [2] 30 32 [2] 36 07 [2] 18 07 [2] 27 1b }

  condition:
    any of them
}