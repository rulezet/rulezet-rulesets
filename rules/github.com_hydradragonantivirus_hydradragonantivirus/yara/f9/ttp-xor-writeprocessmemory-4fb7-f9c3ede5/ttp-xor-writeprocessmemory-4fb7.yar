rule TTP_XOR_WriteProcessMemory_4fb7 {
  strings:
    $key_4fb7 = { 18 c5 [2] 2a e7 [2] 2c d2 [2] 02 d2 [2] 3d ce }

  condition:
    any of them
}