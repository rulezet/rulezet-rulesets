rule TTP_XOR_WriteProcessMemory_19b7 {
  strings:
    $key_19b7 = { 4e c5 [2] 7c e7 [2] 7a d2 [2] 54 d2 [2] 6b ce }

  condition:
    any of them
}