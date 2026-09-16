rule TTP_XOR_WriteProcessMemory_84a8 {
  strings:
    $key_84a8 = { d3 da [2] e1 f8 [2] e7 cd [2] c9 cd [2] f6 d1 }

  condition:
    any of them
}