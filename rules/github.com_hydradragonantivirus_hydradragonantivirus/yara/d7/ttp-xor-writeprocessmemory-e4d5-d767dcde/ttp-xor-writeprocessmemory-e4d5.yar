rule TTP_XOR_WriteProcessMemory_e4d5 {
  strings:
    $key_e4d5 = { b3 a7 [2] 81 85 [2] 87 b0 [2] a9 b0 [2] 96 ac }

  condition:
    any of them
}