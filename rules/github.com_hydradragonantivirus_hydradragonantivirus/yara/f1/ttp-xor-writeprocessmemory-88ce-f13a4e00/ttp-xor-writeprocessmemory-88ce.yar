rule TTP_XOR_WriteProcessMemory_88ce {
  strings:
    $key_88ce = { df bc [2] ed 9e [2] eb ab [2] c5 ab [2] fa b7 }

  condition:
    any of them
}