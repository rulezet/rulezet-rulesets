rule TTP_XOR_WriteProcessMemory_8478 {
  strings:
    $key_8478 = { d3 0a [2] e1 28 [2] e7 1d [2] c9 1d [2] f6 01 }

  condition:
    any of them
}