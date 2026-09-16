rule TTP_XOR_WriteProcessMemory_9673 {
  strings:
    $key_9673 = { c1 01 [2] f3 23 [2] f5 16 [2] db 16 [2] e4 0a }

  condition:
    any of them
}