rule TTP_XOR_WriteProcessMemory_8847 {
  strings:
    $key_8847 = { df 35 [2] ed 17 [2] eb 22 [2] c5 22 [2] fa 3e }

  condition:
    any of them
}