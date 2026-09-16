rule TTP_XOR_WriteProcessMemory_aab0 {
  strings:
    $key_aab0 = { fd c2 [2] cf e0 [2] c9 d5 [2] e7 d5 [2] d8 c9 }

  condition:
    any of them
}