rule TTP_XOR_WriteProcessMemory_8806 {
  strings:
    $key_8806 = { df 74 [2] ed 56 [2] eb 63 [2] c5 63 [2] fa 7f }

  condition:
    any of them
}