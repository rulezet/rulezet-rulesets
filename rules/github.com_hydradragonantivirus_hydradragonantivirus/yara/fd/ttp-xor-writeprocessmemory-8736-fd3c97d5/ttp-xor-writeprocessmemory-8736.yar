rule TTP_XOR_WriteProcessMemory_8736 {
  strings:
    $key_8736 = { d0 44 [2] e2 66 [2] e4 53 [2] ca 53 [2] f5 4f }

  condition:
    any of them
}