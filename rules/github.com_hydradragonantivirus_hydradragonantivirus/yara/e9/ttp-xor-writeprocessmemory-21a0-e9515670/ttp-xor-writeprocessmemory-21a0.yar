rule TTP_XOR_WriteProcessMemory_21a0 {
  strings:
    $key_21a0 = { 76 d2 [2] 44 f0 [2] 42 c5 [2] 6c c5 [2] 53 d9 }

  condition:
    any of them
}