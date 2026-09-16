rule TTP_XOR_WriteProcessMemory_9397 {
  strings:
    $key_9397 = { c4 e5 [2] f6 c7 [2] f0 f2 [2] de f2 [2] e1 ee }

  condition:
    any of them
}