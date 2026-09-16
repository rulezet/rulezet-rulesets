rule TTP_XOR_WriteProcessMemory_60f0 {
  strings:
    $key_60f0 = { 37 82 [2] 05 a0 [2] 03 95 [2] 2d 95 [2] 12 89 }

  condition:
    any of them
}