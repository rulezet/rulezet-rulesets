rule TTP_XOR_WriteProcessMemory_7791 {
  strings:
    $key_7791 = { 20 e3 [2] 12 c1 [2] 14 f4 [2] 3a f4 [2] 05 e8 }

  condition:
    any of them
}