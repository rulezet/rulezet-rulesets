rule TTP_XOR_WriteProcessMemory_76e0 {
  strings:
    $key_76e0 = { 21 92 [2] 13 b0 [2] 15 85 [2] 3b 85 [2] 04 99 }

  condition:
    any of them
}