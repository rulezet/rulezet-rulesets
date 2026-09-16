rule TTP_XOR_WriteProcessMemory_3a07 {
  strings:
    $key_3a07 = { 6d 75 [2] 5f 57 [2] 59 62 [2] 77 62 [2] 48 7e }

  condition:
    any of them
}