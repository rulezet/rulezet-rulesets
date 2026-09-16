rule TTP_XOR_WriteProcessMemory_58a6 {
  strings:
    $key_58a6 = { 0f d4 [2] 3d f6 [2] 3b c3 [2] 15 c3 [2] 2a df }

  condition:
    any of them
}