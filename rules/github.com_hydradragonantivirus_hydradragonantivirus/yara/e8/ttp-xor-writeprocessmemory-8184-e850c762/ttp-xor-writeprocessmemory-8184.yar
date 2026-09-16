rule TTP_XOR_WriteProcessMemory_8184 {
  strings:
    $key_8184 = { d6 f6 [2] e4 d4 [2] e2 e1 [2] cc e1 [2] f3 fd }

  condition:
    any of them
}