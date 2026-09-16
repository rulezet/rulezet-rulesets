rule TTP_XOR_WriteProcessMemory_51b7 {
  strings:
    $key_51b7 = { 06 c5 [2] 34 e7 [2] 32 d2 [2] 1c d2 [2] 23 ce }

  condition:
    any of them
}