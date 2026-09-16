rule TTP_XOR_WriteProcessMemory_b881 {
  strings:
    $key_b881 = { ef f3 [2] dd d1 [2] db e4 [2] f5 e4 [2] ca f8 }

  condition:
    any of them
}