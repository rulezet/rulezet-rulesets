rule TTP_XOR_WriteProcessMemory_4ab7 {
  strings:
    $key_4ab7 = { 1d c5 [2] 2f e7 [2] 29 d2 [2] 07 d2 [2] 38 ce }

  condition:
    any of them
}