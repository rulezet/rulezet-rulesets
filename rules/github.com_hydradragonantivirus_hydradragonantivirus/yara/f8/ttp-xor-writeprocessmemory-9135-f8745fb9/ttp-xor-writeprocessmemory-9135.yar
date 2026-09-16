rule TTP_XOR_WriteProcessMemory_9135 {
  strings:
    $key_9135 = { c6 47 [2] f4 65 [2] f2 50 [2] dc 50 [2] e3 4c }

  condition:
    any of them
}