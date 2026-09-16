rule TTP_XOR_WriteProcessMemory_87e2 {
  strings:
    $key_87e2 = { d0 90 [2] e2 b2 [2] e4 87 [2] ca 87 [2] f5 9b }

  condition:
    any of them
}