rule TTP_XOR_WriteProcessMemory_1507 {
  strings:
    $key_1507 = { 42 75 [2] 70 57 [2] 76 62 [2] 58 62 [2] 67 7e }

  condition:
    any of them
}