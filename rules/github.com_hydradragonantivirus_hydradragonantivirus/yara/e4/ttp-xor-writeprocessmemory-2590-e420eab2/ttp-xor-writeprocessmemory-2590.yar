rule TTP_XOR_WriteProcessMemory_2590 {
  strings:
    $key_2590 = { 72 e2 [2] 40 c0 [2] 46 f5 [2] 68 f5 [2] 57 e9 }

  condition:
    any of them
}