rule TTP_XOR_WriteProcessMemory_60e2 {
  strings:
    $key_60e2 = { 37 90 [2] 05 b2 [2] 03 87 [2] 2d 87 [2] 12 9b }

  condition:
    any of them
}