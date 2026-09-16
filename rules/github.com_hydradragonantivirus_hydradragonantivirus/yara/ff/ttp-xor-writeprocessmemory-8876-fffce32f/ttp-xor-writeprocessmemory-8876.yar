rule TTP_XOR_WriteProcessMemory_8876 {
  strings:
    $key_8876 = { df 04 [2] ed 26 [2] eb 13 [2] c5 13 [2] fa 0f }

  condition:
    any of them
}