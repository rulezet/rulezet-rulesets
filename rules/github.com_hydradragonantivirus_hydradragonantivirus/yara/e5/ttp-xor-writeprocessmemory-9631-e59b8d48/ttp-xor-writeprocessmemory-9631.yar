rule TTP_XOR_WriteProcessMemory_9631 {
  strings:
    $key_9631 = { c1 43 [2] f3 61 [2] f5 54 [2] db 54 [2] e4 48 }

  condition:
    any of them
}