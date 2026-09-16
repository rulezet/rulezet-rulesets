rule TTP_XOR_WriteProcessMemory_77d5 {
  strings:
    $key_77d5 = { 20 a7 [2] 12 85 [2] 14 b0 [2] 3a b0 [2] 05 ac }

  condition:
    any of them
}