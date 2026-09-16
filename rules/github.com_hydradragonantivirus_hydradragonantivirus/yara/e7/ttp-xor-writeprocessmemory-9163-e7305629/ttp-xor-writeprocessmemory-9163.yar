rule TTP_XOR_WriteProcessMemory_9163 {
  strings:
    $key_9163 = { c6 11 [2] f4 33 [2] f2 06 [2] dc 06 [2] e3 1a }

  condition:
    any of them
}