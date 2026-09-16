rule TTP_XOR_WriteProcessMemory_a6b7 {
  strings:
    $key_a6b7 = { f1 c5 [2] c3 e7 [2] c5 d2 [2] eb d2 [2] d4 ce }

  condition:
    any of them
}