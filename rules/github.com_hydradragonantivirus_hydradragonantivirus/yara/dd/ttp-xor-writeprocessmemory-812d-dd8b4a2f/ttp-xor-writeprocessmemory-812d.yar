rule TTP_XOR_WriteProcessMemory_812d {
  strings:
    $key_812d = { d6 5f [2] e4 7d [2] e2 48 [2] cc 48 [2] f3 54 }

  condition:
    any of them
}