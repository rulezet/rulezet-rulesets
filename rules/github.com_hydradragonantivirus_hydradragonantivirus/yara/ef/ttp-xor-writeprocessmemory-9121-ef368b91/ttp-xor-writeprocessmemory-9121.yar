rule TTP_XOR_WriteProcessMemory_9121 {
  strings:
    $key_9121 = { c6 53 [2] f4 71 [2] f2 44 [2] dc 44 [2] e3 58 }

  condition:
    any of them
}