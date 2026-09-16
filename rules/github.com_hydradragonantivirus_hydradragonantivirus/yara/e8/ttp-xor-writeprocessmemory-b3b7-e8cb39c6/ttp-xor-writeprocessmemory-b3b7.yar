rule TTP_XOR_WriteProcessMemory_b3b7 {
  strings:
    $key_b3b7 = { e4 c5 [2] d6 e7 [2] d0 d2 [2] fe d2 [2] c1 ce }

  condition:
    any of them
}