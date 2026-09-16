rule TTP_XOR_WriteProcessMemory_957e {
  strings:
    $key_957e = { c2 0c [2] f0 2e [2] f6 1b [2] d8 1b [2] e7 07 }

  condition:
    any of them
}