rule TTP_XOR_WriteProcessMemory_8462 {
  strings:
    $key_8462 = { d3 10 [2] e1 32 [2] e7 07 [2] c9 07 [2] f6 1b }

  condition:
    any of them
}