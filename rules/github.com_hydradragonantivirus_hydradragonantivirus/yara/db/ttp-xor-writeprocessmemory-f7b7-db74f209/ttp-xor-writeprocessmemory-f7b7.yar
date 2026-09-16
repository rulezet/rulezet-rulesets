rule TTP_XOR_WriteProcessMemory_f7b7 {
  strings:
    $key_f7b7 = { a0 c5 [2] 92 e7 [2] 94 d2 [2] ba d2 [2] 85 ce }

  condition:
    any of them
}