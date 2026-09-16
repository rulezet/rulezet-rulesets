rule TTP_XOR_WriteProcessMemory_8870 {
  strings:
    $key_8870 = { df 02 [2] ed 20 [2] eb 15 [2] c5 15 [2] fa 09 }

  condition:
    any of them
}