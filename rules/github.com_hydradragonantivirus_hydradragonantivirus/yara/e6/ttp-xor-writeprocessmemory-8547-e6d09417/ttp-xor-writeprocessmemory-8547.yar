rule TTP_XOR_WriteProcessMemory_8547 {
  strings:
    $key_8547 = { d2 35 [2] e0 17 [2] e6 22 [2] c8 22 [2] f7 3e }

  condition:
    any of them
}