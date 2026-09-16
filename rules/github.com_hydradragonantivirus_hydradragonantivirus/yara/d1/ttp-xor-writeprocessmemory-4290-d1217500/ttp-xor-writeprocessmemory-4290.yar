rule TTP_XOR_WriteProcessMemory_4290 {
  strings:
    $key_4290 = { 15 e2 [2] 27 c0 [2] 21 f5 [2] 0f f5 [2] 30 e9 }

  condition:
    any of them
}