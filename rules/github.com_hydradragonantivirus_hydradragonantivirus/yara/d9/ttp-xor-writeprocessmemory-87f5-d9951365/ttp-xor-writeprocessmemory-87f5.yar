rule TTP_XOR_WriteProcessMemory_87f5 {
  strings:
    $key_87f5 = { d0 87 [2] e2 a5 [2] e4 90 [2] ca 90 [2] f5 8c }

  condition:
    any of them
}