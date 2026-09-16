rule TTP_XOR_WriteProcessMemory_96ca {
  strings:
    $key_96ca = { c1 b8 [2] f3 9a [2] f5 af [2] db af [2] e4 b3 }

  condition:
    any of them
}