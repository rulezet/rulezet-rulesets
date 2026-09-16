rule TTP_XOR_WriteProcessMemory_6323 {
  strings:
    $key_6323 = { 34 51 [2] 06 73 [2] 00 46 [2] 2e 46 [2] 11 5a }

  condition:
    any of them
}