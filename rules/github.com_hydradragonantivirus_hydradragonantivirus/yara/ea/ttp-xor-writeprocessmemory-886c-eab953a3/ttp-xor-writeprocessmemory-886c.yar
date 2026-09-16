rule TTP_XOR_WriteProcessMemory_886c {
  strings:
    $key_886c = { df 1e [2] ed 3c [2] eb 09 [2] c5 09 [2] fa 15 }

  condition:
    any of them
}