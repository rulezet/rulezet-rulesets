rule TTP_XOR_WriteProcessMemory_9100 {
  strings:
    $key_9100 = { c6 72 [2] f4 50 [2] f2 65 [2] dc 65 [2] e3 79 }

  condition:
    any of them
}