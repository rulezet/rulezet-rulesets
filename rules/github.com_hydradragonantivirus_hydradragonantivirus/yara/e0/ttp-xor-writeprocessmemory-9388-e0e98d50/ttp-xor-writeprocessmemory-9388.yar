rule TTP_XOR_WriteProcessMemory_9388 {
  strings:
    $key_9388 = { c4 fa [2] f6 d8 [2] f0 ed [2] de ed [2] e1 f1 }

  condition:
    any of them
}