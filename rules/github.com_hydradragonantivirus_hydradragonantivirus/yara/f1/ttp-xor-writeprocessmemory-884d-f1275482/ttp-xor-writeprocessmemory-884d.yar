rule TTP_XOR_WriteProcessMemory_884d {
  strings:
    $key_884d = { df 3f [2] ed 1d [2] eb 28 [2] c5 28 [2] fa 34 }

  condition:
    any of them
}