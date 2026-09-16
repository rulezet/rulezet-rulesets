rule TTP_XOR_WriteProcessMemory_8856 {
  strings:
    $key_8856 = { df 24 [2] ed 06 [2] eb 33 [2] c5 33 [2] fa 2f }

  condition:
    any of them
}