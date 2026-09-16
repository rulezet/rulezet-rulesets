rule TTP_XOR_WriteProcessMemory_9137 {
  strings:
    $key_9137 = { c6 45 [2] f4 67 [2] f2 52 [2] dc 52 [2] e3 4e }

  condition:
    any of them
}