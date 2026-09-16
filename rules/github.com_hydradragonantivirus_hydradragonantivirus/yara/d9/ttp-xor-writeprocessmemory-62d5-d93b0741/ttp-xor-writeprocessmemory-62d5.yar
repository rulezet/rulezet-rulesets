rule TTP_XOR_WriteProcessMemory_62d5 {
  strings:
    $key_62d5 = { 35 a7 [2] 07 85 [2] 01 b0 [2] 2f b0 [2] 10 ac }

  condition:
    any of them
}