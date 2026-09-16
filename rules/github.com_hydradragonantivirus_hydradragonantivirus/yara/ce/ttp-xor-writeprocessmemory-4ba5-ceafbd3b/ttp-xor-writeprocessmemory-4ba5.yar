rule TTP_XOR_WriteProcessMemory_4ba5 {
  strings:
    $key_4ba5 = { 1c d7 [2] 2e f5 [2] 28 c0 [2] 06 c0 [2] 39 dc }

  condition:
    any of them
}