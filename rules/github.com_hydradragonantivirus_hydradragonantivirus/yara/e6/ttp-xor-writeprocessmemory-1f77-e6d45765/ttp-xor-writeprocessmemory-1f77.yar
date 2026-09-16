rule TTP_XOR_WriteProcessMemory_1f77 {
  strings:
    $key_1f77 = { 48 05 [2] 7a 27 [2] 7c 12 [2] 52 12 [2] 6d 0e }

  condition:
    any of them
}