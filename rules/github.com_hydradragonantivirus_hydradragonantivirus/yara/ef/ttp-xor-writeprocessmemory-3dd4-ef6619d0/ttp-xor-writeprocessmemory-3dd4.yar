rule TTP_XOR_WriteProcessMemory_3dd4 {
  strings:
    $key_3dd4 = { 6a a6 [2] 58 84 [2] 5e b1 [2] 70 b1 [2] 4f ad }

  condition:
    any of them
}