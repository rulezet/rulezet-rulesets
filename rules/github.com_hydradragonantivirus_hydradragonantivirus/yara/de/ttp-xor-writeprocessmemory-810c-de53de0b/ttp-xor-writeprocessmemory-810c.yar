rule TTP_XOR_WriteProcessMemory_810c {
  strings:
    $key_810c = { d6 7e [2] e4 5c [2] e2 69 [2] cc 69 [2] f3 75 }

  condition:
    any of them
}