rule TTP_XOR_WriteProcessMemory_3a06 {
  strings:
    $key_3a06 = { 6d 74 [2] 5f 56 [2] 59 63 [2] 77 63 [2] 48 7f }

  condition:
    any of them
}