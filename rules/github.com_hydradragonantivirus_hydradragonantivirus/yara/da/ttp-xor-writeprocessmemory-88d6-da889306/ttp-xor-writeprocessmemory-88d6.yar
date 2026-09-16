rule TTP_XOR_WriteProcessMemory_88d6 {
  strings:
    $key_88d6 = { df a4 [2] ed 86 [2] eb b3 [2] c5 b3 [2] fa af }

  condition:
    any of them
}