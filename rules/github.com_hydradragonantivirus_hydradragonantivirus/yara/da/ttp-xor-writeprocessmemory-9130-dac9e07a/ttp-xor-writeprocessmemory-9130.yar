rule TTP_XOR_WriteProcessMemory_9130 {
  strings:
    $key_9130 = { c6 42 [2] f4 60 [2] f2 55 [2] dc 55 [2] e3 49 }

  condition:
    any of them
}