rule TTP_XOR_WriteProcessMemory_6527 {
  strings:
    $key_6527 = { 32 55 [2] 00 77 [2] 06 42 [2] 28 42 [2] 17 5e }

  condition:
    any of them
}