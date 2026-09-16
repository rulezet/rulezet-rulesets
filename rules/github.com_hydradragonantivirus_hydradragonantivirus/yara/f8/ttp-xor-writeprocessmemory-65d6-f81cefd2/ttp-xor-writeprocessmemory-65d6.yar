rule TTP_XOR_WriteProcessMemory_65d6 {
  strings:
    $key_65d6 = { 32 a4 [2] 00 86 [2] 06 b3 [2] 28 b3 [2] 17 af }

  condition:
    any of them
}