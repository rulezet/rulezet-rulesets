rule TTP_XOR_WriteProcessMemory_973d {
  strings:
    $key_973d = { c0 4f [2] f2 6d [2] f4 58 [2] da 58 [2] e5 44 }

  condition:
    any of them
}