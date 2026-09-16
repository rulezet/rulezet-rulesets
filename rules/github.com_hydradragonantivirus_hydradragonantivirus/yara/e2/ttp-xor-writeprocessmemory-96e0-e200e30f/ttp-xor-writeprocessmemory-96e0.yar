rule TTP_XOR_WriteProcessMemory_96e0 {
  strings:
    $key_96e0 = { c1 92 [2] f3 b0 [2] f5 85 [2] db 85 [2] e4 99 }

  condition:
    any of them
}