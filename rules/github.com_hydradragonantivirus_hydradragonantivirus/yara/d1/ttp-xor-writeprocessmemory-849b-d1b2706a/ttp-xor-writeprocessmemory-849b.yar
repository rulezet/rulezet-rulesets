rule TTP_XOR_WriteProcessMemory_849b {
  strings:
    $key_849b = { d3 e9 [2] e1 cb [2] e7 fe [2] c9 fe [2] f6 e2 }

  condition:
    any of them
}