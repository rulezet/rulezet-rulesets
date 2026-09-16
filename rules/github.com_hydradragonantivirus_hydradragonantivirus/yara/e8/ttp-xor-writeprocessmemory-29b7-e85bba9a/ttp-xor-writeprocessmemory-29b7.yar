rule TTP_XOR_WriteProcessMemory_29b7 {
  strings:
    $key_29b7 = { 7e c5 [2] 4c e7 [2] 4a d2 [2] 64 d2 [2] 5b ce }

  condition:
    any of them
}