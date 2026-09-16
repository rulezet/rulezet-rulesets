rule TTP_XOR_WriteProcessMemory_844d {
  strings:
    $key_844d = { d3 3f [2] e1 1d [2] e7 28 [2] c9 28 [2] f6 34 }

  condition:
    any of them
}