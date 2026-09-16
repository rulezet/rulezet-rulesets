rule TTP_XOR_WriteProcessMemory_0eb7 {
  strings:
    $key_0eb7 = { 59 c5 [2] 6b e7 [2] 6d d2 [2] 43 d2 [2] 7c ce }

  condition:
    any of them
}