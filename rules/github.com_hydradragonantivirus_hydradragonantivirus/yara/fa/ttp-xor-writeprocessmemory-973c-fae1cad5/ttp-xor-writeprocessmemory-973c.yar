rule TTP_XOR_WriteProcessMemory_973c {
  strings:
    $key_973c = { c0 4e [2] f2 6c [2] f4 59 [2] da 59 [2] e5 45 }

  condition:
    any of them
}