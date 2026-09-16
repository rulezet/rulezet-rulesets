rule TTP_XOR_WriteProcessMemory_8803 {
  strings:
    $key_8803 = { df 71 [2] ed 53 [2] eb 66 [2] c5 66 [2] fa 7a }

  condition:
    any of them
}