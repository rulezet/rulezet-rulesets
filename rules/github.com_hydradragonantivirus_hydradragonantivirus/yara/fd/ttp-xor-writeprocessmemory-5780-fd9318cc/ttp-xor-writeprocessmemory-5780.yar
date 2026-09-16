rule TTP_XOR_WriteProcessMemory_5780 {
  strings:
    $key_5780 = { 00 f2 [2] 32 d0 [2] 34 e5 [2] 1a e5 [2] 25 f9 }

  condition:
    any of them
}