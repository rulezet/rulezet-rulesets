rule TTP_XOR_WriteProcessMemory_9657 {
  strings:
    $key_9657 = { c1 25 [2] f3 07 [2] f5 32 [2] db 32 [2] e4 2e }

  condition:
    any of them
}