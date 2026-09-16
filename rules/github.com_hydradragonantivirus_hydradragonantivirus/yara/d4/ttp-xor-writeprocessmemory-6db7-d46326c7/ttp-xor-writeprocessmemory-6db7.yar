rule TTP_XOR_WriteProcessMemory_6db7 {
  strings:
    $key_6db7 = { 3a c5 [2] 08 e7 [2] 0e d2 [2] 20 d2 [2] 1f ce }

  condition:
    any of them
}