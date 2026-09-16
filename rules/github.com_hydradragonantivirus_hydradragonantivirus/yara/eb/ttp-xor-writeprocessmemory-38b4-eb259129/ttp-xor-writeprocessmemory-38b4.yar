rule TTP_XOR_WriteProcessMemory_38b4 {
  strings:
    $key_38b4 = { 6f c6 [2] 5d e4 [2] 5b d1 [2] 75 d1 [2] 4a cd }

  condition:
    any of them
}