rule TTP_XOR_WriteProcessMemory_fdb4 {
  strings:
    $key_fdb4 = { aa c6 [2] 98 e4 [2] 9e d1 [2] b0 d1 [2] 8f cd }

  condition:
    any of them
}