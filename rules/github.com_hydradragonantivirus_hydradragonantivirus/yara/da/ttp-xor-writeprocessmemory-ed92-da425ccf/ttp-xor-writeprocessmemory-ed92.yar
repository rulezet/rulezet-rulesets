rule TTP_XOR_WriteProcessMemory_ed92 {
  strings:
    $key_ed92 = { ba e0 [2] 88 c2 [2] 8e f7 [2] a0 f7 [2] 9f eb }

  condition:
    any of them
}