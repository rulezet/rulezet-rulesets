rule TTP_XOR_WriteProcessMemory_9180 {
  strings:
    $key_9180 = { c6 f2 [2] f4 d0 [2] f2 e5 [2] dc e5 [2] e3 f9 }

  condition:
    any of them
}