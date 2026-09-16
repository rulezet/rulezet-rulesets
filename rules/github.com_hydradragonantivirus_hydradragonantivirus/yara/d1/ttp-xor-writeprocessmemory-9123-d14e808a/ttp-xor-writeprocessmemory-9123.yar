rule TTP_XOR_WriteProcessMemory_9123 {
  strings:
    $key_9123 = { c6 51 [2] f4 73 [2] f2 46 [2] dc 46 [2] e3 5a }

  condition:
    any of them
}