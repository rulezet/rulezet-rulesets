rule TTP_XOR_WriteProcessMemory_8585 {
  strings:
    $key_8585 = { d2 f7 [2] e0 d5 [2] e6 e0 [2] c8 e0 [2] f7 fc }

  condition:
    any of them
}