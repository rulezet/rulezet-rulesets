rule TTP_XOR_WriteProcessMemory_3f77 {
  strings:
    $key_3f77 = { 68 05 [2] 5a 27 [2] 5c 12 [2] 72 12 [2] 4d 0e }

  condition:
    any of them
}