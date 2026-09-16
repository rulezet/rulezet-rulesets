rule TTP_XOR_WriteProcessMemory_44e0 {
  strings:
    $key_44e0 = { 13 92 [2] 21 b0 [2] 27 85 [2] 09 85 [2] 36 99 }

  condition:
    any of them
}