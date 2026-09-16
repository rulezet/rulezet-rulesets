rule TTP_XOR_WriteProcessMemory_25e7 {
  strings:
    $key_25e7 = { 72 95 [2] 40 b7 [2] 46 82 [2] 68 82 [2] 57 9e }

  condition:
    any of them
}