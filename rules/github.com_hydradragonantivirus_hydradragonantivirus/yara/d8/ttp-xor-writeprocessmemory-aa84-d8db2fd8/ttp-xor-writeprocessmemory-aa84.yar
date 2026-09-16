rule TTP_XOR_WriteProcessMemory_aa84 {
  strings:
    $key_aa84 = { fd f6 [2] cf d4 [2] c9 e1 [2] e7 e1 [2] d8 fd }

  condition:
    any of them
}