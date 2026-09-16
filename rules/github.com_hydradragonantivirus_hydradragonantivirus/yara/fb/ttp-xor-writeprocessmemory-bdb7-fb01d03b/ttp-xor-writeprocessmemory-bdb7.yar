rule TTP_XOR_WriteProcessMemory_bdb7 {
  strings:
    $key_bdb7 = { ea c5 [2] d8 e7 [2] de d2 [2] f0 d2 [2] cf ce }

  condition:
    any of them
}