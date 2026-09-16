rule TTP_XOR_WriteProcessMemory_8445 {
  strings:
    $key_8445 = { d3 37 [2] e1 15 [2] e7 20 [2] c9 20 [2] f6 3c }

  condition:
    any of them
}