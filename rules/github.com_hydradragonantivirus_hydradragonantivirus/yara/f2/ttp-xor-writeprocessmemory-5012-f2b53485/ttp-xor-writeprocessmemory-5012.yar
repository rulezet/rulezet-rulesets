rule TTP_XOR_WriteProcessMemory_5012 {
  strings:
    $key_5012 = { 07 60 [2] 35 42 [2] 33 77 [2] 1d 77 [2] 22 6b }

  condition:
    any of them
}