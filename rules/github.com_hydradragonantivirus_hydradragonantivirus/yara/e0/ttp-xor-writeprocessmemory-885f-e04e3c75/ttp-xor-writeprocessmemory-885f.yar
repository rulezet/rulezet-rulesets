rule TTP_XOR_WriteProcessMemory_885f {
  strings:
    $key_885f = { df 2d [2] ed 0f [2] eb 3a [2] c5 3a [2] fa 26 }

  condition:
    any of them
}