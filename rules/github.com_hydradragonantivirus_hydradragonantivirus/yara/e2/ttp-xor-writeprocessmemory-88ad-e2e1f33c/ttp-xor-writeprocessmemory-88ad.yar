rule TTP_XOR_WriteProcessMemory_88ad {
  strings:
    $key_88ad = { df df [2] ed fd [2] eb c8 [2] c5 c8 [2] fa d4 }

  condition:
    any of them
}