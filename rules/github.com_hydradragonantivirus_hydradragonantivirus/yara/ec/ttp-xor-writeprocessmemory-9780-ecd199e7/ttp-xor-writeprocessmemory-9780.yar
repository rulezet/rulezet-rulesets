rule TTP_XOR_WriteProcessMemory_9780 {
  strings:
    $key_9780 = { c0 f2 [2] f2 d0 [2] f4 e5 [2] da e5 [2] e5 f9 }

  condition:
    any of them
}