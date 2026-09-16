rule TTP_XOR_WriteProcessMemory_93b7 {
  strings:
    $key_93b7 = { c4 c5 [2] f6 e7 [2] f0 d2 [2] de d2 [2] e1 ce }

  condition:
    any of them
}