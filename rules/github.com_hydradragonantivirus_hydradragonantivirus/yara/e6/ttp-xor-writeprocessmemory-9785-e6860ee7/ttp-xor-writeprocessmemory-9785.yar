rule TTP_XOR_WriteProcessMemory_9785 {
  strings:
    $key_9785 = { c0 f7 [2] f2 d5 [2] f4 e0 [2] da e0 [2] e5 fc }

  condition:
    any of them
}