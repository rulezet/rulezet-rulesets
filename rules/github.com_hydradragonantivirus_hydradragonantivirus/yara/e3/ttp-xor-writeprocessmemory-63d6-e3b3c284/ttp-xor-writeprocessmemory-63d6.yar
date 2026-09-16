rule TTP_XOR_WriteProcessMemory_63d6 {
  strings:
    $key_63d6 = { 34 a4 [2] 06 86 [2] 00 b3 [2] 2e b3 [2] 11 af }

  condition:
    any of them
}