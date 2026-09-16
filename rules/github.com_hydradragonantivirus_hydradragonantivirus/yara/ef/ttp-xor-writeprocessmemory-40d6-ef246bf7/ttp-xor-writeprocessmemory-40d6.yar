rule TTP_XOR_WriteProcessMemory_40d6 {
  strings:
    $key_40d6 = { 17 a4 [2] 25 86 [2] 23 b3 [2] 0d b3 [2] 32 af }

  condition:
    any of them
}