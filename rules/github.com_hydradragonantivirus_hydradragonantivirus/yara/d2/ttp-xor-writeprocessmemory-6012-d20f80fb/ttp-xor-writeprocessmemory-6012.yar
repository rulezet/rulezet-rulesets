rule TTP_XOR_WriteProcessMemory_6012 {
  strings:
    $key_6012 = { 37 60 [2] 05 42 [2] 03 77 [2] 2d 77 [2] 12 6b }

  condition:
    any of them
}