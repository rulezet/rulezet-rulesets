rule TTP_XOR_WriteProcessMemory_4d92 {
  strings:
    $key_4d92 = { 1a e0 [2] 28 c2 [2] 2e f7 [2] 00 f7 [2] 3f eb }

  condition:
    any of them
}