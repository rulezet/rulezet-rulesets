rule TTP_XOR_WriteProcessMemory_9614 {
  strings:
    $key_9614 = { c1 66 [2] f3 44 [2] f5 71 [2] db 71 [2] e4 6d }

  condition:
    any of them
}