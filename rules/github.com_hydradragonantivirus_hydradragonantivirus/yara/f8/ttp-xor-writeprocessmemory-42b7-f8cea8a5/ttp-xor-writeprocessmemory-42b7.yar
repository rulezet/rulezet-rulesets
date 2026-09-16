rule TTP_XOR_WriteProcessMemory_42b7 {
  strings:
    $key_42b7 = { 15 c5 [2] 27 e7 [2] 21 d2 [2] 0f d2 [2] 30 ce }

  condition:
    any of them
}