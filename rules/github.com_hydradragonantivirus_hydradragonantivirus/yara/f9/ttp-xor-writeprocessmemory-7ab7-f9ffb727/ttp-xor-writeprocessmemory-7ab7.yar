rule TTP_XOR_WriteProcessMemory_7ab7 {
  strings:
    $key_7ab7 = { 2d c5 [2] 1f e7 [2] 19 d2 [2] 37 d2 [2] 08 ce }

  condition:
    any of them
}