rule TTP_XOR_WriteProcessMemory_8404 {
  strings:
    $key_8404 = { d3 76 [2] e1 54 [2] e7 61 [2] c9 61 [2] f6 7d }

  condition:
    any of them
}