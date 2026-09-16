rule TTP_XOR_WriteProcessMemory_9398 {
  strings:
    $key_9398 = { c4 ea [2] f6 c8 [2] f0 fd [2] de fd [2] e1 e1 }

  condition:
    any of them
}