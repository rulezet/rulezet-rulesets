rule TTP_XOR_WriteProcessMemory_87f9 {
  strings:
    $key_87f9 = { d0 8b [2] e2 a9 [2] e4 9c [2] ca 9c [2] f5 80 }

  condition:
    any of them
}