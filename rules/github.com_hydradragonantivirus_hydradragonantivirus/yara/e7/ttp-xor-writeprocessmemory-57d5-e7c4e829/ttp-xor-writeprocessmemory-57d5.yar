rule TTP_XOR_WriteProcessMemory_57d5 {
  strings:
    $key_57d5 = { 00 a7 [2] 32 85 [2] 34 b0 [2] 1a b0 [2] 25 ac }

  condition:
    any of them
}