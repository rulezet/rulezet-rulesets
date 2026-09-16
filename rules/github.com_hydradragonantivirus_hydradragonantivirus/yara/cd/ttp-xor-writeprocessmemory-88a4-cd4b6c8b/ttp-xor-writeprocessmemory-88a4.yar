rule TTP_XOR_WriteProcessMemory_88a4 {
  strings:
    $key_88a4 = { df d6 [2] ed f4 [2] eb c1 [2] c5 c1 [2] fa dd }

  condition:
    any of them
}