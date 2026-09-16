rule TTP_XOR_WriteProcessMemory_8567 {
  strings:
    $key_8567 = { d2 15 [2] e0 37 [2] e6 02 [2] c8 02 [2] f7 1e }

  condition:
    any of them
}