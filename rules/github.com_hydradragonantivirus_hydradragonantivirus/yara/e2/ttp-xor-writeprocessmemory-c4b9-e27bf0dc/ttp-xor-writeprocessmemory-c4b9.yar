rule TTP_XOR_WriteProcessMemory_c4b9 {
  strings:
    $key_c4b9 = { 93 cb [2] a1 e9 [2] a7 dc [2] 89 dc [2] b6 c0 }

  condition:
    any of them
}