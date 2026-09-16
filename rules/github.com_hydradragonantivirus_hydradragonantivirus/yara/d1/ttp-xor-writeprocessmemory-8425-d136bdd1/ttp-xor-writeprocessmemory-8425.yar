rule TTP_XOR_WriteProcessMemory_8425 {
  strings:
    $key_8425 = { d3 57 [2] e1 75 [2] e7 40 [2] c9 40 [2] f6 5c }

  condition:
    any of them
}