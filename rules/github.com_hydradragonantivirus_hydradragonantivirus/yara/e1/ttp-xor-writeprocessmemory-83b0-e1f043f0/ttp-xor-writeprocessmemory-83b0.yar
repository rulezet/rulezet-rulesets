rule TTP_XOR_WriteProcessMemory_83b0 {
  strings:
    $key_83b0 = { d4 c2 [2] e6 e0 [2] e0 d5 [2] ce d5 [2] f1 c9 }

  condition:
    any of them
}