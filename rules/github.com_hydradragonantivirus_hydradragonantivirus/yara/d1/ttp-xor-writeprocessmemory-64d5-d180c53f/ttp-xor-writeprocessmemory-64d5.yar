rule TTP_XOR_WriteProcessMemory_64d5 {
  strings:
    $key_64d5 = { 33 a7 [2] 01 85 [2] 07 b0 [2] 29 b0 [2] 16 ac }

  condition:
    any of them
}