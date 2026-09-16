rule TTP_XOR_WriteProcessMemory_80b7 {
  strings:
    $key_80b7 = { d7 c5 [2] e5 e7 [2] e3 d2 [2] cd d2 [2] f2 ce }

  condition:
    any of them
}