rule TTP_XOR_WriteProcessMemory_ceb7 {
  strings:
    $key_ceb7 = { 99 c5 [2] ab e7 [2] ad d2 [2] 83 d2 [2] bc ce }

  condition:
    any of them
}