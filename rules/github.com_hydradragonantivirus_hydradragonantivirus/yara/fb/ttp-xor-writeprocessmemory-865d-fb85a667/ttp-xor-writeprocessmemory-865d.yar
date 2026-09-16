rule TTP_XOR_WriteProcessMemory_865d {
  strings:
    $key_865d = { d1 2f [2] e3 0d [2] e5 38 [2] cb 38 [2] f4 24 }

  condition:
    any of them
}