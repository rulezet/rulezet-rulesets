rule TTP_XOR_WriteProcessMemory_60e0 {
  strings:
    $key_60e0 = { 37 92 [2] 05 b0 [2] 03 85 [2] 2d 85 [2] 12 99 }

  condition:
    any of them
}