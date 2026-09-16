rule TTP_XOR_WriteProcessMemory_57a8 {
  strings:
    $key_57a8 = { 00 da [2] 32 f8 [2] 34 cd [2] 1a cd [2] 25 d1 }

  condition:
    any of them
}