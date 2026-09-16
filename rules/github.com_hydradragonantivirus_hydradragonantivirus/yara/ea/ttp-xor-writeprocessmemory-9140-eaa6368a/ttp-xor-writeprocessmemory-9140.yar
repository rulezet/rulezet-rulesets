rule TTP_XOR_WriteProcessMemory_9140 {
  strings:
    $key_9140 = { c6 32 [2] f4 10 [2] f2 25 [2] dc 25 [2] e3 39 }

  condition:
    any of them
}