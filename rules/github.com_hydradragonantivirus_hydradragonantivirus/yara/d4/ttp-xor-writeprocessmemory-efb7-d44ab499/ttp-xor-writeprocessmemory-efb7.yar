rule TTP_XOR_WriteProcessMemory_efb7 {
  strings:
    $key_efb7 = { b8 c5 [2] 8a e7 [2] 8c d2 [2] a2 d2 [2] 9d ce }

  condition:
    any of them
}