rule TTP_XOR_WriteProcessMemory_8564 {
  strings:
    $key_8564 = { d2 16 [2] e0 34 [2] e6 01 [2] c8 01 [2] f7 1d }

  condition:
    any of them
}