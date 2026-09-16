rule TTP_XOR_WriteProcessMemory_887e {
  strings:
    $key_887e = { df 0c [2] ed 2e [2] eb 1b [2] c5 1b [2] fa 07 }

  condition:
    any of them
}