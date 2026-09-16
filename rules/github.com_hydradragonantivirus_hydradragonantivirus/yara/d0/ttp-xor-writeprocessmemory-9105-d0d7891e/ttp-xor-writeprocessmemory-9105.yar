rule TTP_XOR_WriteProcessMemory_9105 {
  strings:
    $key_9105 = { c6 77 [2] f4 55 [2] f2 60 [2] dc 60 [2] e3 7c }

  condition:
    any of them
}