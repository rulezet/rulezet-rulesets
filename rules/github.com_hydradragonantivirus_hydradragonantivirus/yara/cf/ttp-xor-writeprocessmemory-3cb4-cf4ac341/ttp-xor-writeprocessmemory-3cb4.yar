rule TTP_XOR_WriteProcessMemory_3cb4 {
  strings:
    $key_3cb4 = { 6b c6 [2] 59 e4 [2] 5f d1 [2] 71 d1 [2] 4e cd }

  condition:
    any of them
}