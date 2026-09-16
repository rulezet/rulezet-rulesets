rule TTP_XOR_WriteProcessMemory_8527 {
  strings:
    $key_8527 = { d2 55 [2] e0 77 [2] e6 42 [2] c8 42 [2] f7 5e }

  condition:
    any of them
}