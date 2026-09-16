rule TTP_XOR_WriteProcessMemory_23a0 {
  strings:
    $key_23a0 = { 74 d2 [2] 46 f0 [2] 40 c5 [2] 6e c5 [2] 51 d9 }

  condition:
    any of them
}