rule TTP_XOR_WriteProcessMemory_87f2 {
  strings:
    $key_87f2 = { d0 80 [2] e2 a2 [2] e4 97 [2] ca 97 [2] f5 8b }

  condition:
    any of them
}