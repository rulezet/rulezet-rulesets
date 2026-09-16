rule TTP_XOR_WriteProcessMemory_8817 {
  strings:
    $key_8817 = { df 65 [2] ed 47 [2] eb 72 [2] c5 72 [2] fa 6e }

  condition:
    any of them
}