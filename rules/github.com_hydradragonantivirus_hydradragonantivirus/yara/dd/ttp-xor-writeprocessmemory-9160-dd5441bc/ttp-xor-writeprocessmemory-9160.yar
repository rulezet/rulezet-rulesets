rule TTP_XOR_WriteProcessMemory_9160 {
  strings:
    $key_9160 = { c6 12 [2] f4 30 [2] f2 05 [2] dc 05 [2] e3 19 }

  condition:
    any of them
}