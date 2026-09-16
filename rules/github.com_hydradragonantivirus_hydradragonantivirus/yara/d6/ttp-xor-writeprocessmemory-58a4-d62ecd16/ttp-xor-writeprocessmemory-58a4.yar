rule TTP_XOR_WriteProcessMemory_58a4 {
  strings:
    $key_58a4 = { 0f d6 [2] 3d f4 [2] 3b c1 [2] 15 c1 [2] 2a dd }

  condition:
    any of them
}