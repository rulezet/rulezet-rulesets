rule TTP_XOR_WriteProcessMemory_925b {
  strings:
    $key_925b = { c5 29 [2] f7 0b [2] f1 3e [2] df 3e [2] e0 22 }

  condition:
    any of them
}