rule TTP_XOR_WriteProcessMemory_65cc {
  strings:
    $key_65cc = { 32 be [2] 00 9c [2] 06 a9 [2] 28 a9 [2] 17 b5 }

  condition:
    any of them
}