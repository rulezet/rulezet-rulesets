rule TTP_XOR_WriteProcessMemory_cab9 {
  strings:
    $key_cab9 = { 9d cb [2] af e9 [2] a9 dc [2] 87 dc [2] b8 c0 }

  condition:
    any of them
}