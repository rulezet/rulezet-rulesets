rule TTP_XOR_WriteProcessMemory_3a02 {
  strings:
    $key_3a02 = { 6d 70 [2] 5f 52 [2] 59 67 [2] 77 67 [2] 48 7b }

  condition:
    any of them
}