rule TTP_XOR_WriteProcessMemory_3a33 {
  strings:
    $key_3a33 = { 6d 41 [2] 5f 63 [2] 59 56 [2] 77 56 [2] 48 4a }

  condition:
    any of them
}