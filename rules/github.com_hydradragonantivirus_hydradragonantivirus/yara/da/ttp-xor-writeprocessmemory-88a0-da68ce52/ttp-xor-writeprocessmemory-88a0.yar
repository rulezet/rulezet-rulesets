rule TTP_XOR_WriteProcessMemory_88a0 {
  strings:
    $key_88a0 = { df d2 [2] ed f0 [2] eb c5 [2] c5 c5 [2] fa d9 }

  condition:
    any of them
}