rule TTP_XOR_WriteProcessMemory_d5b9 {
  strings:
    $key_d5b9 = { 82 cb [2] b0 e9 [2] b6 dc [2] 98 dc [2] a7 c0 }

  condition:
    any of them
}