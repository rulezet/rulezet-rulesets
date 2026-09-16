rule TTP_XOR_WriteProcessMemory_fcb7 {
  strings:
    $key_fcb7 = { ab c5 [2] 99 e7 [2] 9f d2 [2] b1 d2 [2] 8e ce }

  condition:
    any of them
}