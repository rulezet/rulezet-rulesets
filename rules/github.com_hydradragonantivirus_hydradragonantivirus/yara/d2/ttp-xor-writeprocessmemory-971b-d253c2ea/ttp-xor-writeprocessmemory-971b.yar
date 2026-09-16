rule TTP_XOR_WriteProcessMemory_971b {
  strings:
    $key_971b = { c0 69 [2] f2 4b [2] f4 7e [2] da 7e [2] e5 62 }

  condition:
    any of them
}