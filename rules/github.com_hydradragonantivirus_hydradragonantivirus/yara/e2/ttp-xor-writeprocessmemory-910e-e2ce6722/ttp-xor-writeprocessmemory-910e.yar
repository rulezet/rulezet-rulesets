rule TTP_XOR_WriteProcessMemory_910e {
  strings:
    $key_910e = { c6 7c [2] f4 5e [2] f2 6b [2] dc 6b [2] e3 77 }

  condition:
    any of them
}