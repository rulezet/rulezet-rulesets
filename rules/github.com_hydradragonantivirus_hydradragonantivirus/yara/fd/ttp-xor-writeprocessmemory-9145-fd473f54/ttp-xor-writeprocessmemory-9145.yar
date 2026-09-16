rule TTP_XOR_WriteProcessMemory_9145 {
  strings:
    $key_9145 = { c6 37 [2] f4 15 [2] f2 20 [2] dc 20 [2] e3 3c }

  condition:
    any of them
}