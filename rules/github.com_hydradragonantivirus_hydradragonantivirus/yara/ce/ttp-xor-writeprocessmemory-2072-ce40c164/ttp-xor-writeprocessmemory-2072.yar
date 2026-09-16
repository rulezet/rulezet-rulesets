rule TTP_XOR_WriteProcessMemory_2072 {
  strings:
    $key_2072 = { 77 00 [2] 45 22 [2] 43 17 [2] 6d 17 [2] 52 0b }

  condition:
    any of them
}