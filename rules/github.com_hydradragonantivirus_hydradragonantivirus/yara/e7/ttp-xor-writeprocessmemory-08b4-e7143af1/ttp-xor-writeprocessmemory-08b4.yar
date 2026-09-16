rule TTP_XOR_WriteProcessMemory_08b4 {
  strings:
    $key_08b4 = { 5f c6 [2] 6d e4 [2] 6b d1 [2] 45 d1 [2] 7a cd }

  condition:
    any of them
}