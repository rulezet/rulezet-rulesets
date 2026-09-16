rule TTP_XOR_WriteProcessMemory_8451 {
  strings:
    $key_8451 = { d3 23 [2] e1 01 [2] e7 34 [2] c9 34 [2] f6 28 }

  condition:
    any of them
}