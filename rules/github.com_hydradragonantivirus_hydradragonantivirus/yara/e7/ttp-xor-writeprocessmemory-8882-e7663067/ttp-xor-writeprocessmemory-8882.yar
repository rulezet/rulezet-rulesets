rule TTP_XOR_WriteProcessMemory_8882 {
  strings:
    $key_8882 = { df f0 [2] ed d2 [2] eb e7 [2] c5 e7 [2] fa fb }

  condition:
    any of them
}