rule TTP_XOR_WriteProcessMemory_7db7 {
  strings:
    $key_7db7 = { 2a c5 [2] 18 e7 [2] 1e d2 [2] 30 d2 [2] 0f ce }

  condition:
    any of them
}