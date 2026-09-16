rule TTP_XOR_WriteProcessMemory_8470 {
  strings:
    $key_8470 = { d3 02 [2] e1 20 [2] e7 15 [2] c9 15 [2] f6 09 }

  condition:
    any of them
}