rule TTP_XOR_WriteProcessMemory_fc90 {
  strings:
    $key_fc90 = { ab e2 [2] 99 c0 [2] 9f f5 [2] b1 f5 [2] 8e e9 }

  condition:
    any of them
}