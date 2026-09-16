rule TTP_XOR_WriteProcessMemory_f1b7 {
  strings:
    $key_f1b7 = { a6 c5 [2] 94 e7 [2] 92 d2 [2] bc d2 [2] 83 ce }

  condition:
    any of them
}