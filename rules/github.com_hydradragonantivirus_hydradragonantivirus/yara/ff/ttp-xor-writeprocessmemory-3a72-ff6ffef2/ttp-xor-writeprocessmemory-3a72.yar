rule TTP_XOR_WriteProcessMemory_3a72 {
  strings:
    $key_3a72 = { 6d 00 [2] 5f 22 [2] 59 17 [2] 77 17 [2] 48 0b }

  condition:
    any of them
}