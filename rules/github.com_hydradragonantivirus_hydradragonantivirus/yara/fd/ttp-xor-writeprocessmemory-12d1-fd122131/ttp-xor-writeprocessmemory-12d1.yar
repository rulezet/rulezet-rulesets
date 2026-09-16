rule TTP_XOR_WriteProcessMemory_12d1 {
  strings:
    $key_12d1 = { 45 a3 [2] 77 81 [2] 71 b4 [2] 5f b4 [2] 60 a8 }

  condition:
    any of them
}