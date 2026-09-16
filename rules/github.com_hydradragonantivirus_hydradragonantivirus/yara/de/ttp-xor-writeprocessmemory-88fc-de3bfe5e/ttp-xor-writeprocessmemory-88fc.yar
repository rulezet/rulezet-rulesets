rule TTP_XOR_WriteProcessMemory_88fc {
  strings:
    $key_88fc = { df 8e [2] ed ac [2] eb 99 [2] c5 99 [2] fa 85 }

  condition:
    any of them
}