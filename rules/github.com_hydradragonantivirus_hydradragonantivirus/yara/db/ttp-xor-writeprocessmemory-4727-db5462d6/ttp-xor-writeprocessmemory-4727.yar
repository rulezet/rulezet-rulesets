rule TTP_XOR_WriteProcessMemory_4727 {
  strings:
    $key_4727 = { 10 55 [2] 22 77 [2] 24 42 [2] 0a 42 [2] 35 5e }

  condition:
    any of them
}