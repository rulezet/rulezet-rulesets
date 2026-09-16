rule TTP_XOR_WriteProcessMemory_5eb7 {
  strings:
    $key_5eb7 = { 09 c5 [2] 3b e7 [2] 3d d2 [2] 13 d2 [2] 2c ce }

  condition:
    any of them
}