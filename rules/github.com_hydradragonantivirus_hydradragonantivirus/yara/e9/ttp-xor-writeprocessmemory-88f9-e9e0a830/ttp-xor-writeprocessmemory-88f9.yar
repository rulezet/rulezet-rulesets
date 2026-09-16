rule TTP_XOR_WriteProcessMemory_88f9 {
  strings:
    $key_88f9 = { df 8b [2] ed a9 [2] eb 9c [2] c5 9c [2] fa 80 }

  condition:
    any of them
}