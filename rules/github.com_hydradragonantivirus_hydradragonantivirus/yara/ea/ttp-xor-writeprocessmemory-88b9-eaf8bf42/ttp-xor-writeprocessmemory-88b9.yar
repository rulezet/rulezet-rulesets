rule TTP_XOR_WriteProcessMemory_88b9 {
  strings:
    $key_88b9 = { df cb [2] ed e9 [2] eb dc [2] c5 dc [2] fa c0 }

  condition:
    any of them
}