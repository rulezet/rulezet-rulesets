rule TTP_XOR_WriteProcessMemory_41b7 {
  strings:
    $key_41b7 = { 16 c5 [2] 24 e7 [2] 22 d2 [2] 0c d2 [2] 33 ce }

  condition:
    any of them
}