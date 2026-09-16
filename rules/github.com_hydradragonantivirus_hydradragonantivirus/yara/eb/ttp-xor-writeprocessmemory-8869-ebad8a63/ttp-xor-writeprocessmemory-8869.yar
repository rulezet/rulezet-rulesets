rule TTP_XOR_WriteProcessMemory_8869 {
  strings:
    $key_8869 = { df 1b [2] ed 39 [2] eb 0c [2] c5 0c [2] fa 10 }

  condition:
    any of them
}