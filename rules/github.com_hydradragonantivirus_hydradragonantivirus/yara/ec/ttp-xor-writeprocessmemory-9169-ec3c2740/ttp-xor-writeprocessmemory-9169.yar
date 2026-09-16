rule TTP_XOR_WriteProcessMemory_9169 {
  strings:
    $key_9169 = { c6 1b [2] f4 39 [2] f2 0c [2] dc 0c [2] e3 10 }

  condition:
    any of them
}