rule TTP_XOR_WriteProcessMemory_62d6 {
  strings:
    $key_62d6 = { 35 a4 [2] 07 86 [2] 01 b3 [2] 2f b3 [2] 10 af }

  condition:
    any of them
}