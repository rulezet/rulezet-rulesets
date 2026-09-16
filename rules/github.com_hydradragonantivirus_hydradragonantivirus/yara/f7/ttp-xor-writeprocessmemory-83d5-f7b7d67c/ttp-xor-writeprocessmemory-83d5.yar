rule TTP_XOR_WriteProcessMemory_83d5 {
  strings:
    $key_83d5 = { d4 a7 [2] e6 85 [2] e0 b0 [2] ce b0 [2] f1 ac }

  condition:
    any of them
}