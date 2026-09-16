rule TTP_XOR_WriteProcessMemory_60e1 {
  strings:
    $key_60e1 = { 37 93 [2] 05 b1 [2] 03 84 [2] 2d 84 [2] 12 98 }

  condition:
    any of them
}