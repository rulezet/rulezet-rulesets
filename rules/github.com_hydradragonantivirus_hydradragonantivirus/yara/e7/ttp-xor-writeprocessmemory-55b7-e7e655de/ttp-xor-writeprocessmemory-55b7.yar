rule TTP_XOR_WriteProcessMemory_55b7 {
  strings:
    $key_55b7 = { 02 c5 [2] 30 e7 [2] 36 d2 [2] 18 d2 [2] 27 ce }

  condition:
    any of them
}