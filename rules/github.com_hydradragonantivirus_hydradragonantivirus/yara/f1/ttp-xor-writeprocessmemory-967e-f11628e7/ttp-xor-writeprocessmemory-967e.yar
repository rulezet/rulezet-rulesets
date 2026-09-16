rule TTP_XOR_WriteProcessMemory_967e {
  strings:
    $key_967e = { c1 0c [2] f3 2e [2] f5 1b [2] db 1b [2] e4 07 }

  condition:
    any of them
}