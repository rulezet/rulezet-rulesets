rule TTP_XOR_WriteProcessMemory_2090 {
  strings:
    $key_2090 = { 77 e2 [2] 45 c0 [2] 43 f5 [2] 6d f5 [2] 52 e9 }

  condition:
    any of them
}