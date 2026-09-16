rule TTP_XOR_WriteProcessMemory_916e {
  strings:
    $key_916e = { c6 1c [2] f4 3e [2] f2 0b [2] dc 0b [2] e3 17 }

  condition:
    any of them
}