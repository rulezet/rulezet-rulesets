rule TTP_XOR_WriteProcessMemory_8458 {
  strings:
    $key_8458 = { d3 2a [2] e1 08 [2] e7 3d [2] c9 3d [2] f6 21 }

  condition:
    any of them
}