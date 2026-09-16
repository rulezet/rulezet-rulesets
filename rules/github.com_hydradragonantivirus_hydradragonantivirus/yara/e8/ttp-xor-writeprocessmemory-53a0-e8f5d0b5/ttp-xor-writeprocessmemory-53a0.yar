rule TTP_XOR_WriteProcessMemory_53a0 {
  strings:
    $key_53a0 = { 04 d2 [2] 36 f0 [2] 30 c5 [2] 1e c5 [2] 21 d9 }

  condition:
    any of them
}