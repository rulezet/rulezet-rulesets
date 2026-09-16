rule TTP_XOR_WriteProcessMemory_10b7 {
  strings:
    $key_10b7 = { 47 c5 [2] 75 e7 [2] 73 d2 [2] 5d d2 [2] 62 ce }

  condition:
    any of them
}