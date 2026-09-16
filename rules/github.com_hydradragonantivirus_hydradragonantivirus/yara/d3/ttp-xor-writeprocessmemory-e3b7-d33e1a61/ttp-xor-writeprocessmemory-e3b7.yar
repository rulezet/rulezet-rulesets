rule TTP_XOR_WriteProcessMemory_e3b7 {
  strings:
    $key_e3b7 = { b4 c5 [2] 86 e7 [2] 80 d2 [2] ae d2 [2] 91 ce }

  condition:
    any of them
}