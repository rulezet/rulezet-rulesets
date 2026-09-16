rule TTP_XOR_WriteProcessMemory_e4b7 {
  strings:
    $key_e4b7 = { b3 c5 [2] 81 e7 [2] 87 d2 [2] a9 d2 [2] 96 ce }

  condition:
    any of them
}