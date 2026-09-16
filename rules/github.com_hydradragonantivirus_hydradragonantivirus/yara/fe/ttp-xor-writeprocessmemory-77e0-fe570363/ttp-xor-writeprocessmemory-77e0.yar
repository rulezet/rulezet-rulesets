rule TTP_XOR_WriteProcessMemory_77e0 {
  strings:
    $key_77e0 = { 20 92 [2] 12 b0 [2] 14 85 [2] 3a 85 [2] 05 99 }

  condition:
    any of them
}