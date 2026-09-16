rule TTP_XOR_WriteProcessMemory_887b {
  strings:
    $key_887b = { df 09 [2] ed 2b [2] eb 1e [2] c5 1e [2] fa 02 }

  condition:
    any of them
}