rule TTP_XOR_WriteProcessMemory_6d92 {
  strings:
    $key_6d92 = { 3a e0 [2] 08 c2 [2] 0e f7 [2] 20 f7 [2] 1f eb }

  condition:
    any of them
}