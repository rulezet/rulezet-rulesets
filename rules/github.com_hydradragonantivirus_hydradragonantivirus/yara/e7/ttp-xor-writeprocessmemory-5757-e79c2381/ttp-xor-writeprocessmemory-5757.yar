rule TTP_XOR_WriteProcessMemory_5757 {
  strings:
    $key_5757 = { 00 25 [2] 32 07 [2] 34 32 [2] 1a 32 [2] 25 2e }

  condition:
    any of them
}