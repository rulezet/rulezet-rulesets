rule TTP_XOR_WriteProcessMemory_856e {
  strings:
    $key_856e = { d2 1c [2] e0 3e [2] e6 0b [2] c8 0b [2] f7 17 }

  condition:
    any of them
}