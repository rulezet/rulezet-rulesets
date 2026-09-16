rule TTP_XOR_WriteProcessMemory_8280 {
  strings:
    $key_8280 = { d5 f2 [2] e7 d0 [2] e1 e5 [2] cf e5 [2] f0 f9 }

  condition:
    any of them
}