rule TTP_XOR_WriteProcessMemory_0d92 {
  strings:
    $key_0d92 = { 5a e0 [2] 68 c2 [2] 6e f7 [2] 40 f7 [2] 7f eb }

  condition:
    any of them
}