rule TTP_XOR_WriteProcessMemory_88c3 {
  strings:
    $key_88c3 = { df b1 [2] ed 93 [2] eb a6 [2] c5 a6 [2] fa ba }

  condition:
    any of them
}