rule TTP_XOR_WriteProcessMemory_9197 {
  strings:
    $key_9197 = { c6 e5 [2] f4 c7 [2] f2 f2 [2] dc f2 [2] e3 ee }

  condition:
    any of them
}