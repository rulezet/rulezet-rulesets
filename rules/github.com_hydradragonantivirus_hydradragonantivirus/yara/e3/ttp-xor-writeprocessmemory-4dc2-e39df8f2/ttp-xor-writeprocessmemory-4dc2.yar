rule TTP_XOR_WriteProcessMemory_4dc2 {
  strings:
    $key_4dc2 = { 1a b0 [2] 28 92 [2] 2e a7 [2] 00 a7 [2] 3f bb }

  condition:
    any of them
}