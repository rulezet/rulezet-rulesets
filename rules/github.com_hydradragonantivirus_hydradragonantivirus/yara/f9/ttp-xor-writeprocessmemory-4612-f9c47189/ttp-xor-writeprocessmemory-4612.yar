rule TTP_XOR_WriteProcessMemory_4612 {
  strings:
    $key_4612 = { 11 60 [2] 23 42 [2] 25 77 [2] 0b 77 [2] 34 6b }

  condition:
    any of them
}