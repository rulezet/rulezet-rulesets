rule TTP_XOR_WriteProcessMemory_84f8 {
  strings:
    $key_84f8 = { d3 8a [2] e1 a8 [2] e7 9d [2] c9 9d [2] f6 81 }

  condition:
    any of them
}