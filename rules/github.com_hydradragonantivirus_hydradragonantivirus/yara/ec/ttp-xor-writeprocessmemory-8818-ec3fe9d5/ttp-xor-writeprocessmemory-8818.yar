rule TTP_XOR_WriteProcessMemory_8818 {
  strings:
    $key_8818 = { df 6a [2] ed 48 [2] eb 7d [2] c5 7d [2] fa 61 }

  condition:
    any of them
}