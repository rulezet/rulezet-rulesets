rule TTP_XOR_WriteProcessMemory_5f77 {
  strings:
    $key_5f77 = { 08 05 [2] 3a 27 [2] 3c 12 [2] 12 12 [2] 2d 0e }

  condition:
    any of them
}