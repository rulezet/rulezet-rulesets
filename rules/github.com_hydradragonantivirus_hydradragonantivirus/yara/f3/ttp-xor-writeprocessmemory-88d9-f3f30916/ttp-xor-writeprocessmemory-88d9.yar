rule TTP_XOR_WriteProcessMemory_88d9 {
  strings:
    $key_88d9 = { df ab [2] ed 89 [2] eb bc [2] c5 bc [2] fa a0 }

  condition:
    any of them
}