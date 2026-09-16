rule TTP_XOR_WriteProcessMemory_35b7 {
  strings:
    $key_35b7 = { 62 c5 [2] 50 e7 [2] 56 d2 [2] 78 d2 [2] 47 ce }

  condition:
    any of them
}