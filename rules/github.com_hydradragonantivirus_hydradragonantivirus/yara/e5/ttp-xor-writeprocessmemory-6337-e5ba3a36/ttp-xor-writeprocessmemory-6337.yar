rule TTP_XOR_WriteProcessMemory_6337 {
  strings:
    $key_6337 = { 34 45 [2] 06 67 [2] 00 52 [2] 2e 52 [2] 11 4e }

  condition:
    any of them
}