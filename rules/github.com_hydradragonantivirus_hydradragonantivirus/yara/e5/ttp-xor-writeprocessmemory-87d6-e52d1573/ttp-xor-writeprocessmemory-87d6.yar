rule TTP_XOR_WriteProcessMemory_87d6 {
  strings:
    $key_87d6 = { d0 a4 [2] e2 86 [2] e4 b3 [2] ca b3 [2] f5 af }

  condition:
    any of them
}