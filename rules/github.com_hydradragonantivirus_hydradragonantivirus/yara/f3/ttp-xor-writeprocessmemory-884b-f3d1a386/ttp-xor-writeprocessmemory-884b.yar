rule TTP_XOR_WriteProcessMemory_884b {
  strings:
    $key_884b = { df 39 [2] ed 1b [2] eb 2e [2] c5 2e [2] fa 32 }

  condition:
    any of them
}