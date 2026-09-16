rule TTP_XOR_WriteProcessMemory_c0b7 {
  strings:
    $key_c0b7 = { 97 c5 [2] a5 e7 [2] a3 d2 [2] 8d d2 [2] b2 ce }

  condition:
    any of them
}