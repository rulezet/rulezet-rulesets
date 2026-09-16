rule TTP_XOR_WriteProcessMemory_83d0 {
  strings:
    $key_83d0 = { d4 a2 [2] e6 80 [2] e0 b5 [2] ce b5 [2] f1 a9 }

  condition:
    any of them
}