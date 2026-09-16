rule TTP_XOR_WriteProcessMemory_d2b7 {
  strings:
    $key_d2b7 = { 85 c5 [2] b7 e7 [2] b1 d2 [2] 9f d2 [2] a0 ce }

  condition:
    any of them
}