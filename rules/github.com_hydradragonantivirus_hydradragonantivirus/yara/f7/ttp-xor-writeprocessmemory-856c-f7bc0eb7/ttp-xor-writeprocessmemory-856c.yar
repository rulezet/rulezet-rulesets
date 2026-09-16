rule TTP_XOR_WriteProcessMemory_856c {
  strings:
    $key_856c = { d2 1e [2] e0 3c [2] e6 09 [2] c8 09 [2] f7 15 }

  condition:
    any of them
}