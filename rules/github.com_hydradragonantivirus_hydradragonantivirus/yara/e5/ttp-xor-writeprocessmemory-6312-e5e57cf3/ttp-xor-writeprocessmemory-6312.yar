rule TTP_XOR_WriteProcessMemory_6312 {
  strings:
    $key_6312 = { 34 60 [2] 06 42 [2] 00 77 [2] 2e 77 [2] 11 6b }

  condition:
    any of them
}