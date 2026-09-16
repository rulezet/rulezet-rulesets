rule TTP_XOR_WriteProcessMemory_7d90 {
  strings:
    $key_7d90 = { 2a e2 [2] 18 c0 [2] 1e f5 [2] 30 f5 [2] 0f e9 }

  condition:
    any of them
}