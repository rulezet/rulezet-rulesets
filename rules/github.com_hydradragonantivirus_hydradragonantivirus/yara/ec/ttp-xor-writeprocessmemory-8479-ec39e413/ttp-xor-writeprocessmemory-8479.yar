rule TTP_XOR_WriteProcessMemory_8479 {
  strings:
    $key_8479 = { d3 0b [2] e1 29 [2] e7 1c [2] c9 1c [2] f6 00 }

  condition:
    any of them
}