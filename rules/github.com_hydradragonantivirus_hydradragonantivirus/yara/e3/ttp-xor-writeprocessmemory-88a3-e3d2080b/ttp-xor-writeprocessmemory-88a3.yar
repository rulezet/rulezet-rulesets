rule TTP_XOR_WriteProcessMemory_88a3 {
  strings:
    $key_88a3 = { df d1 [2] ed f3 [2] eb c6 [2] c5 c6 [2] fa da }

  condition:
    any of them
}