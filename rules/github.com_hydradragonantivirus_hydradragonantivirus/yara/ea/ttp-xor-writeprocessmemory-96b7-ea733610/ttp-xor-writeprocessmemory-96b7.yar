rule TTP_XOR_WriteProcessMemory_96b7 {
  strings:
    $key_96b7 = { c1 c5 [2] f3 e7 [2] f5 d2 [2] db d2 [2] e4 ce }

  condition:
    any of them
}