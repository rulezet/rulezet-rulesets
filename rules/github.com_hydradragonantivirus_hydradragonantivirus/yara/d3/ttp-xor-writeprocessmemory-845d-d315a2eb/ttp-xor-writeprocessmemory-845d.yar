rule TTP_XOR_WriteProcessMemory_845d {
  strings:
    $key_845d = { d3 2f [2] e1 0d [2] e7 38 [2] c9 38 [2] f6 24 }

  condition:
    any of them
}