rule TTP_XOR_WriteProcessMemory_8460 {
  strings:
    $key_8460 = { d3 12 [2] e1 30 [2] e7 05 [2] c9 05 [2] f6 19 }

  condition:
    any of them
}