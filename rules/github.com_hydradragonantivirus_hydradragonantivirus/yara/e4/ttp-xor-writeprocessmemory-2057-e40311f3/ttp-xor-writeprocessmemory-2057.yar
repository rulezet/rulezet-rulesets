rule TTP_XOR_WriteProcessMemory_2057 {
  strings:
    $key_2057 = { 77 25 [2] 45 07 [2] 43 32 [2] 6d 32 [2] 52 2e }

  condition:
    any of them
}