rule TTP_XOR_WriteProcessMemory_88ca {
  strings:
    $key_88ca = { df b8 [2] ed 9a [2] eb af [2] c5 af [2] fa b3 }

  condition:
    any of them
}