rule TTP_XOR_WriteProcessMemory_88a5 {
  strings:
    $key_88a5 = { df d7 [2] ed f5 [2] eb c0 [2] c5 c0 [2] fa dc }

  condition:
    any of them
}