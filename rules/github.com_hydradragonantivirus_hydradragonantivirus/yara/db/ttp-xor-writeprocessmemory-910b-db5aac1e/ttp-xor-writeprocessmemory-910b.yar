rule TTP_XOR_WriteProcessMemory_910b {
  strings:
    $key_910b = { c6 79 [2] f4 5b [2] f2 6e [2] dc 6e [2] e3 72 }

  condition:
    any of them
}