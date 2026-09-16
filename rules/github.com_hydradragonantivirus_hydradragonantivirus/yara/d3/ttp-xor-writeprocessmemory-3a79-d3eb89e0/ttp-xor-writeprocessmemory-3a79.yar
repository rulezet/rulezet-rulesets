rule TTP_XOR_WriteProcessMemory_3a79 {
  strings:
    $key_3a79 = { 6d 0b [2] 5f 29 [2] 59 1c [2] 77 1c [2] 48 00 }

  condition:
    any of them
}