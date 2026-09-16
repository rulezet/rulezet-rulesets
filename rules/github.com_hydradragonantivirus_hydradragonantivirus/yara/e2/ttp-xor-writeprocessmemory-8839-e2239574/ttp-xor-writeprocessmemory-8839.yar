rule TTP_XOR_WriteProcessMemory_8839 {
  strings:
    $key_8839 = { df 4b [2] ed 69 [2] eb 5c [2] c5 5c [2] fa 40 }

  condition:
    any of them
}