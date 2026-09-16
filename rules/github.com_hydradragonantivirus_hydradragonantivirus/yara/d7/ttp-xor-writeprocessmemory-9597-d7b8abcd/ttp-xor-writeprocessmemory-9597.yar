rule TTP_XOR_WriteProcessMemory_9597 {
  strings:
    $key_9597 = { c2 e5 [2] f0 c7 [2] f6 f2 [2] d8 f2 [2] e7 ee }

  condition:
    any of them
}