rule TTP_XOR_WriteProcessMemory_b884 {
  strings:
    $key_b884 = { ef f6 [2] dd d4 [2] db e1 [2] f5 e1 [2] ca fd }

  condition:
    any of them
}