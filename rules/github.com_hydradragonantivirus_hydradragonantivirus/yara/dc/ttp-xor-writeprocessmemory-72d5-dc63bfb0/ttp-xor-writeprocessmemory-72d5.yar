rule TTP_XOR_WriteProcessMemory_72d5 {
  strings:
    $key_72d5 = { 25 a7 [2] 17 85 [2] 11 b0 [2] 3f b0 [2] 00 ac }

  condition:
    any of them
}