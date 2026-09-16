rule TTP_XOR_WriteProcessMemory_5db7 {
  strings:
    $key_5db7 = { 0a c5 [2] 38 e7 [2] 3e d2 [2] 10 d2 [2] 2f ce }

  condition:
    any of them
}