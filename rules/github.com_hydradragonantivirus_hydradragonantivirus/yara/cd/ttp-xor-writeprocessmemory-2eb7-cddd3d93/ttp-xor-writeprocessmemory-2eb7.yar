rule TTP_XOR_WriteProcessMemory_2eb7 {
  strings:
    $key_2eb7 = { 79 c5 [2] 4b e7 [2] 4d d2 [2] 63 d2 [2] 5c ce }

  condition:
    any of them
}