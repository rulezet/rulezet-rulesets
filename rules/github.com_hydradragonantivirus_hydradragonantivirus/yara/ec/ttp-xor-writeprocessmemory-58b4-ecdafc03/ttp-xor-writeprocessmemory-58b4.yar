rule TTP_XOR_WriteProcessMemory_58b4 {
  strings:
    $key_58b4 = { 0f c6 [2] 3d e4 [2] 3b d1 [2] 15 d1 [2] 2a cd }

  condition:
    any of them
}