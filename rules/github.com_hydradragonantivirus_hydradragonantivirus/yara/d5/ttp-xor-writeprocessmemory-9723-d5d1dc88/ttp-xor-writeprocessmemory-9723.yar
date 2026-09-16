rule TTP_XOR_WriteProcessMemory_9723 {
  strings:
    $key_9723 = { c0 51 [2] f2 73 [2] f4 46 [2] da 46 [2] e5 5a }

  condition:
    any of them
}