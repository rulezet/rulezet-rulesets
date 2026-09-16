rule TTP_XOR_WriteProcessMemory_8533 {
  strings:
    $key_8533 = { d2 41 [2] e0 63 [2] e6 56 [2] c8 56 [2] f7 4a }

  condition:
    any of them
}