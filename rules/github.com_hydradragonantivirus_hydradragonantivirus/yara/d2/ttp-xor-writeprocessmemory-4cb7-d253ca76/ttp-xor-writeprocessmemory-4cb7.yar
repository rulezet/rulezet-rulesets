rule TTP_XOR_WriteProcessMemory_4cb7 {
  strings:
    $key_4cb7 = { 1b c5 [2] 29 e7 [2] 2f d2 [2] 01 d2 [2] 3e ce }

  condition:
    any of them
}