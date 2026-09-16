rule TTP_XOR_WriteProcessMemory_3ab7 {
  strings:
    $key_3ab7 = { 6d c5 [2] 5f e7 [2] 59 d2 [2] 77 d2 [2] 48 ce }

  condition:
    any of them
}