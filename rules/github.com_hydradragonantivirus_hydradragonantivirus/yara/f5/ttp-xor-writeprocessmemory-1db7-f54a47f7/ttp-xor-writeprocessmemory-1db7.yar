rule TTP_XOR_WriteProcessMemory_1db7 {
  strings:
    $key_1db7 = { 4a c5 [2] 78 e7 [2] 7e d2 [2] 50 d2 [2] 6f ce }

  condition:
    any of them
}