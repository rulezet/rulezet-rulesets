rule TTP_XOR_WriteProcessMemory_87d0 {
  strings:
    $key_87d0 = { d0 a2 [2] e2 80 [2] e4 b5 [2] ca b5 [2] f5 a9 }

  condition:
    any of them
}