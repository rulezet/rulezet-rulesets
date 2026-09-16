rule TTP_XOR_WriteProcessMemory_20b7 {
  strings:
    $key_20b7 = { 77 c5 [2] 45 e7 [2] 43 d2 [2] 6d d2 [2] 52 ce }

  condition:
    any of them
}