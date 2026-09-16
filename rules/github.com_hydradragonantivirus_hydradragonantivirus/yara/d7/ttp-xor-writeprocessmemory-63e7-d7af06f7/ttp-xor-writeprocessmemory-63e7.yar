rule TTP_XOR_WriteProcessMemory_63e7 {
  strings:
    $key_63e7 = { 34 95 [2] 06 b7 [2] 00 82 [2] 2e 82 [2] 11 9e }

  condition:
    any of them
}