rule TTP_XOR_WriteProcessMemory_07d1 {
  strings:
    $key_07d1 = { 50 a3 [2] 62 81 [2] 64 b4 [2] 4a b4 [2] 75 a8 }

  condition:
    any of them
}