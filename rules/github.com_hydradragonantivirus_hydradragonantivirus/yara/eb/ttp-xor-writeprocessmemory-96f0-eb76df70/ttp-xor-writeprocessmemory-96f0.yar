rule TTP_XOR_WriteProcessMemory_96f0 {
  strings:
    $key_96f0 = { c1 82 [2] f3 a0 [2] f5 95 [2] db 95 [2] e4 89 }

  condition:
    any of them
}