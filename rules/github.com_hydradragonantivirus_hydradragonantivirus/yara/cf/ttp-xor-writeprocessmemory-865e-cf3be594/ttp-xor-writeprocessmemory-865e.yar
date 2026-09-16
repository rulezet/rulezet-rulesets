rule TTP_XOR_WriteProcessMemory_865e {
  strings:
    $key_865e = { d1 2c [2] e3 0e [2] e5 3b [2] cb 3b [2] f4 27 }

  condition:
    any of them
}