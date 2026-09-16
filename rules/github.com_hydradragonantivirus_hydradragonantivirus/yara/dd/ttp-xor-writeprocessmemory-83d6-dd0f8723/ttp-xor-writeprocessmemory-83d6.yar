rule TTP_XOR_WriteProcessMemory_83d6 {
  strings:
    $key_83d6 = { d4 a4 [2] e6 86 [2] e0 b3 [2] ce b3 [2] f1 af }

  condition:
    any of them
}