rule TTP_XOR_WriteProcessMemory_1b92 {
  strings:
    $key_1b92 = { 4c e0 [2] 7e c2 [2] 78 f7 [2] 56 f7 [2] 69 eb }

  condition:
    any of them
}