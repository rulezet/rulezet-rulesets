rule TTP_XOR_WriteProcessMemory_23f0 {
  strings:
    $key_23f0 = { 74 82 [2] 46 a0 [2] 40 95 [2] 6e 95 [2] 51 89 }

  condition:
    any of them
}