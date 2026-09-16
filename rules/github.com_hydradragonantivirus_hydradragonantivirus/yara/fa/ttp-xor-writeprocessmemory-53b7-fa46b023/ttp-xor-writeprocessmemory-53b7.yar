rule TTP_XOR_WriteProcessMemory_53b7 {
  strings:
    $key_53b7 = { 04 c5 [2] 36 e7 [2] 30 d2 [2] 1e d2 [2] 21 ce }

  condition:
    any of them
}