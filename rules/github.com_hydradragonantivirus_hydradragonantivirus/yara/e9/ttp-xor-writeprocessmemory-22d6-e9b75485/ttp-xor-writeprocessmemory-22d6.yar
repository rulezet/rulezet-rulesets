rule TTP_XOR_WriteProcessMemory_22d6 {
  strings:
    $key_22d6 = { 75 a4 [2] 47 86 [2] 41 b3 [2] 6f b3 [2] 50 af }

  condition:
    any of them
}