rule TTP_XOR_WriteProcessMemory_9097 {
  strings:
    $key_9097 = { c7 e5 [2] f5 c7 [2] f3 f2 [2] dd f2 [2] e2 ee }

  condition:
    any of them
}