rule TTP_XOR_WriteProcessMemory_0bb9 {
  strings:
    $key_0bb9 = { 5c cb [2] 6e e9 [2] 68 dc [2] 46 dc [2] 79 c0 }

  condition:
    any of them
}