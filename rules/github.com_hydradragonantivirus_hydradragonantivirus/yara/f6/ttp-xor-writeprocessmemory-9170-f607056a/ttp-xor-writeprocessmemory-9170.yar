rule TTP_XOR_WriteProcessMemory_9170 {
  strings:
    $key_9170 = { c6 02 [2] f4 20 [2] f2 15 [2] dc 15 [2] e3 09 }

  condition:
    any of them
}