rule TTP_XOR_WriteProcessMemory_8512 {
  strings:
    $key_8512 = { d2 60 [2] e0 42 [2] e6 77 [2] c8 77 [2] f7 6b }

  condition:
    any of them
}