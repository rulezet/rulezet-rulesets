rule TTP_XOR_WriteProcessMemory_25a0 {
  strings:
    $key_25a0 = { 72 d2 [2] 40 f0 [2] 46 c5 [2] 68 c5 [2] 57 d9 }

  condition:
    any of them
}