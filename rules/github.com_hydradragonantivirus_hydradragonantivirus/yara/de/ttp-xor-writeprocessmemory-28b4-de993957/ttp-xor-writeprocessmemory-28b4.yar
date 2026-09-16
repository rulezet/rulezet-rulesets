rule TTP_XOR_WriteProcessMemory_28b4 {
  strings:
    $key_28b4 = { 7f c6 [2] 4d e4 [2] 4b d1 [2] 65 d1 [2] 5a cd }

  condition:
    any of them
}