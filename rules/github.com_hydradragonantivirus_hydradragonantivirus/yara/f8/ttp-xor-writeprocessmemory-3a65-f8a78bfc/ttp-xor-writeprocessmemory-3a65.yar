rule TTP_XOR_WriteProcessMemory_3a65 {
  strings:
    $key_3a65 = { 6d 17 [2] 5f 35 [2] 59 00 [2] 77 00 [2] 48 1c }

  condition:
    any of them
}