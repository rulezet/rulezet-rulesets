rule TTP_XOR_WriteProcessMemory_dab7 {
  strings:
    $key_dab7 = { 8d c5 [2] bf e7 [2] b9 d2 [2] 97 d2 [2] a8 ce }

  condition:
    any of them
}