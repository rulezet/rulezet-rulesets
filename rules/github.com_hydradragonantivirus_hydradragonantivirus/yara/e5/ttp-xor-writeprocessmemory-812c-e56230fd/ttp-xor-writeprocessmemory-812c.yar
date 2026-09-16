rule TTP_XOR_WriteProcessMemory_812c {
  strings:
    $key_812c = { d6 5e [2] e4 7c [2] e2 49 [2] cc 49 [2] f3 55 }

  condition:
    any of them
}