rule TTP_XOR_WriteProcessMemory_64b7 {
  strings:
    $key_64b7 = { 33 c5 [2] 01 e7 [2] 07 d2 [2] 29 d2 [2] 16 ce }

  condition:
    any of them
}