rule TTP_XOR_WriteProcessMemory_5980 {
  strings:
    $key_5980 = { 0e f2 [2] 3c d0 [2] 3a e5 [2] 14 e5 [2] 2b f9 }

  condition:
    any of them
}