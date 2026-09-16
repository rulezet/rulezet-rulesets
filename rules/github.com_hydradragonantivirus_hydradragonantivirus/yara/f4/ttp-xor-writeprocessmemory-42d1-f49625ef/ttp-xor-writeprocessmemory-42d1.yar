rule TTP_XOR_WriteProcessMemory_42d1 {
  strings:
    $key_42d1 = { 15 a3 [2] 27 81 [2] 21 b4 [2] 0f b4 [2] 30 a8 }

  condition:
    any of them
}