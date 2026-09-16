rule TTP_XOR_WriteProcessMemory_0ba5 {
  strings:
    $key_0ba5 = { 5c d7 [2] 6e f5 [2] 68 c0 [2] 46 c0 [2] 79 dc }

  condition:
    any of them
}