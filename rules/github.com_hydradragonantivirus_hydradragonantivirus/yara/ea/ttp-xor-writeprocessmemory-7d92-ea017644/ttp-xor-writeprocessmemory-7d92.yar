rule TTP_XOR_WriteProcessMemory_7d92 {
  strings:
    $key_7d92 = { 2a e0 [2] 18 c2 [2] 1e f7 [2] 30 f7 [2] 0f eb }

  condition:
    any of them
}