rule TTP_XOR_WriteProcessMemory_74a0 {
  strings:
    $key_74a0 = { 23 d2 [2] 11 f0 [2] 17 c5 [2] 39 c5 [2] 06 d9 }

  condition:
    any of them
}