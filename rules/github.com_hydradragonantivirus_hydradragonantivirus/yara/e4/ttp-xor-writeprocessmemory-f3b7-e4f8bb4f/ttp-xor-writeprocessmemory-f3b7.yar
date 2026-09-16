rule TTP_XOR_WriteProcessMemory_f3b7 {
  strings:
    $key_f3b7 = { a4 c5 [2] 96 e7 [2] 90 d2 [2] be d2 [2] 81 ce }

  condition:
    any of them
}