rule TTP_XOR_WriteProcessMemory_9685 {
  strings:
    $key_9685 = { c1 f7 [2] f3 d5 [2] f5 e0 [2] db e0 [2] e4 fc }

  condition:
    any of them
}