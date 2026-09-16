rule TTP_XOR_WriteProcessMemory_aa82 {
  strings:
    $key_aa82 = { fd f0 [2] cf d2 [2] c9 e7 [2] e7 e7 [2] d8 fb }

  condition:
    any of them
}