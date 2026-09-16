rule TTP_XOR_WriteProcessMemory_83e1 {
  strings:
    $key_83e1 = { d4 93 [2] e6 b1 [2] e0 84 [2] ce 84 [2] f1 98 }

  condition:
    any of them
}