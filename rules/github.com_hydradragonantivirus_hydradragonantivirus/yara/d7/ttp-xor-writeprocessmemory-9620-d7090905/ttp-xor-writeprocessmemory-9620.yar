rule TTP_XOR_WriteProcessMemory_9620 {
  strings:
    $key_9620 = { c1 52 [2] f3 70 [2] f5 45 [2] db 45 [2] e4 59 }

  condition:
    any of them
}