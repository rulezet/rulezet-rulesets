rule TTP_XOR_WriteProcessMemory_71b7 {
  strings:
    $key_71b7 = { 26 c5 [2] 14 e7 [2] 12 d2 [2] 3c d2 [2] 03 ce }

  condition:
    any of them
}