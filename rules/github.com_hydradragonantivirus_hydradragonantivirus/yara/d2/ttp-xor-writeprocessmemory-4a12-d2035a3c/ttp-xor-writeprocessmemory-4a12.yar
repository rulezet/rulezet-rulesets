rule TTP_XOR_WriteProcessMemory_4a12 {
  strings:
    $key_4a12 = { 1d 60 [2] 2f 42 [2] 29 77 [2] 07 77 [2] 38 6b }

  condition:
    any of them
}