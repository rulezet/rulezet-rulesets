rule TTP_XOR_WriteProcessMemory_2cb4 {
  strings:
    $key_2cb4 = { 7b c6 [2] 49 e4 [2] 4f d1 [2] 61 d1 [2] 5e cd }

  condition:
    any of them
}