rule TTP_XOR_WriteProcessMemory_88d2 {
  strings:
    $key_88d2 = { df a0 [2] ed 82 [2] eb b7 [2] c5 b7 [2] fa ab }

  condition:
    any of them
}