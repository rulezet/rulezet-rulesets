rule TTP_XOR_WriteProcessMemory_8800 {
  strings:
    $key_8800 = { df 72 [2] ed 50 [2] eb 65 [2] c5 65 [2] fa 79 }

  condition:
    any of them
}