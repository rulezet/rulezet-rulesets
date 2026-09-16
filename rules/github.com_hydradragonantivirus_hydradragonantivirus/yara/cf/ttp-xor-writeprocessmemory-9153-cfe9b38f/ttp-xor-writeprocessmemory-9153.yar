rule TTP_XOR_WriteProcessMemory_9153 {
  strings:
    $key_9153 = { c6 21 [2] f4 03 [2] f2 36 [2] dc 36 [2] e3 2a }

  condition:
    any of them
}