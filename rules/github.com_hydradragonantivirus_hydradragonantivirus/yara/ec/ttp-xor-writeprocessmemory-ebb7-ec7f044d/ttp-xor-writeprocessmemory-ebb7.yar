rule TTP_XOR_WriteProcessMemory_ebb7 {
  strings:
    $key_ebb7 = { bc c5 [2] 8e e7 [2] 88 d2 [2] a6 d2 [2] 99 ce }

  condition:
    any of them
}