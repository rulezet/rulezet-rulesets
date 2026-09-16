rule TTP_XOR_WriteProcessMemory_6cb4 {
  strings:
    $key_6cb4 = { 3b c6 [2] 09 e4 [2] 0f d1 [2] 21 d1 [2] 1e cd }

  condition:
    any of them
}