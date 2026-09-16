rule TTP_XOR_WriteProcessMemory_9692 {
  strings:
    $key_9692 = { c1 e0 [2] f3 c2 [2] f5 f7 [2] db f7 [2] e4 eb }

  condition:
    any of them
}