rule TTP_XOR_WriteProcessMemory_ffb7 {
  strings:
    $key_ffb7 = { a8 c5 [2] 9a e7 [2] 9c d2 [2] b2 d2 [2] 8d ce }

  condition:
    any of them
}