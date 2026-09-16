rule TTP_XOR_WriteProcessMemory_916b {
  strings:
    $key_916b = { c6 19 [2] f4 3b [2] f2 0e [2] dc 0e [2] e3 12 }

  condition:
    any of them
}