rule TTP_XOR_WriteProcessMemory_854b {
  strings:
    $key_854b = { d2 39 [2] e0 1b [2] e6 2e [2] c8 2e [2] f7 32 }

  condition:
    any of them
}