rule TTP_XOR_WriteProcessMemory_9161 {
  strings:
    $key_9161 = { c6 13 [2] f4 31 [2] f2 04 [2] dc 04 [2] e3 18 }

  condition:
    any of them
}