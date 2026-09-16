rule TTP_XOR_WriteProcessMemory_c4b7 {
  strings:
    $key_c4b7 = { 93 c5 [2] a1 e7 [2] a7 d2 [2] 89 d2 [2] b6 ce }

  condition:
    any of them
}