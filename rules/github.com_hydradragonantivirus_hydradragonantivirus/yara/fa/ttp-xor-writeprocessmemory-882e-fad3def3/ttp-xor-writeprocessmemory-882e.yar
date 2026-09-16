rule TTP_XOR_WriteProcessMemory_882e {
  strings:
    $key_882e = { df 5c [2] ed 7e [2] eb 4b [2] c5 4b [2] fa 57 }

  condition:
    any of them
}