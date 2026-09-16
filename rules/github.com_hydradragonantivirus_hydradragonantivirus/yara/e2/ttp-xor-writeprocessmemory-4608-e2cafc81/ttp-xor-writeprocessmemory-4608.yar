rule TTP_XOR_WriteProcessMemory_4608 {
  strings:
    $key_4608 = { 11 7a [2] 23 58 [2] 25 6d [2] 0b 6d [2] 34 71 }

  condition:
    any of them
}