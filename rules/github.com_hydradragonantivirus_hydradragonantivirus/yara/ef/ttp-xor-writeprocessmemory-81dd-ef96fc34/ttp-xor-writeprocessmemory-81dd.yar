rule TTP_XOR_WriteProcessMemory_81dd {
  strings:
    $key_81dd = { d6 af [2] e4 8d [2] e2 b8 [2] cc b8 [2] f3 a4 }

  condition:
    any of them
}