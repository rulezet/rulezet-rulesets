rule TTP_XOR_WriteProcessMemory_1580 {
  strings:
    $key_1580 = { 42 f2 [2] 70 d0 [2] 76 e5 [2] 58 e5 [2] 67 f9 }

  condition:
    any of them
}