rule TTP_XOR_WriteProcessMemory_63f3 {
  strings:
    $key_63f3 = { 34 81 [2] 06 a3 [2] 00 96 [2] 2e 96 [2] 11 8a }

  condition:
    any of them
}