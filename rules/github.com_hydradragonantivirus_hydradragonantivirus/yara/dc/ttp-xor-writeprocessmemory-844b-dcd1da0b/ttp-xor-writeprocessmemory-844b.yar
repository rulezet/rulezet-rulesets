rule TTP_XOR_WriteProcessMemory_844b {
  strings:
    $key_844b = { d3 39 [2] e1 1b [2] e7 2e [2] c9 2e [2] f6 32 }

  condition:
    any of them
}