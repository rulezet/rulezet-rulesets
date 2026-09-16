rule TTP_XOR_WriteProcessMemory_7d91 {
  strings:
    $key_7d91 = { 2a e3 [2] 18 c1 [2] 1e f4 [2] 30 f4 [2] 0f e8 }

  condition:
    any of them
}