rule TTP_XOR_WriteProcessMemory_20d5 {
  strings:
    $key_20d5 = { 77 a7 [2] 45 85 [2] 43 b0 [2] 6d b0 [2] 52 ac }

  condition:
    any of them
}