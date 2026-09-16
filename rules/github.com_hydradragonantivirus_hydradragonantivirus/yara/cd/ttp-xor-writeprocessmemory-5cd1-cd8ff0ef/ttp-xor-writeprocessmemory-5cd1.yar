rule TTP_XOR_WriteProcessMemory_5cd1 {
  strings:
    $key_5cd1 = { 0b a3 [2] 39 81 [2] 3f b4 [2] 11 b4 [2] 2e a8 }

  condition:
    any of them
}