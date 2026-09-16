rule TTP_XOR_WriteProcessMemory_907e {
  strings:
    $key_907e = { c7 0c [2] f5 2e [2] f3 1b [2] dd 1b [2] e2 07 }

  condition:
    any of them
}