rule TTP_XOR_WriteProcessMemory_814b {
  strings:
    $key_814b = { d6 39 [2] e4 1b [2] e2 2e [2] cc 2e [2] f3 32 }

  condition:
    any of them
}