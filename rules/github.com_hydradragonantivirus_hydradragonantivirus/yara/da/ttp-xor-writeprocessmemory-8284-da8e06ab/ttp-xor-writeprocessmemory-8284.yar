rule TTP_XOR_WriteProcessMemory_8284 {
  strings:
    $key_8284 = { d5 f6 [2] e7 d4 [2] e1 e1 [2] cf e1 [2] f0 fd }

  condition:
    any of them
}