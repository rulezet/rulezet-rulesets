rule TTP_XOR_WriteProcessMemory_59b7 {
  strings:
    $key_59b7 = { 0e c5 [2] 3c e7 [2] 3a d2 [2] 14 d2 [2] 2b ce }

  condition:
    any of them
}