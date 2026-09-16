rule TTP_XOR_WriteProcessMemory_5927 {
  strings:
    $key_5927 = { 0e 55 [2] 3c 77 [2] 3a 42 [2] 14 42 [2] 2b 5e }

  condition:
    any of them
}