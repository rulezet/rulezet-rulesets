rule TTP_XOR_WriteProcessMemory_8205 {
  strings:
    $key_8205 = { d5 77 [2] e7 55 [2] e1 60 [2] cf 60 [2] f0 7c }

  condition:
    any of them
}