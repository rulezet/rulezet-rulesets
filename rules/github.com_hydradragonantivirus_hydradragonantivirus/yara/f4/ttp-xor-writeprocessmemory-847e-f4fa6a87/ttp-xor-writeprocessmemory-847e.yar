rule TTP_XOR_WriteProcessMemory_847e {
  strings:
    $key_847e = { d3 0c [2] e1 2e [2] e7 1b [2] c9 1b [2] f6 07 }

  condition:
    any of them
}