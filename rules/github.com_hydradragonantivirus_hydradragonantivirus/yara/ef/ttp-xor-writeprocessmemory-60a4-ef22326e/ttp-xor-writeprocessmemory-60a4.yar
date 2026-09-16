rule TTP_XOR_WriteProcessMemory_60a4 {
  strings:
    $key_60a4 = { 37 d6 [2] 05 f4 [2] 03 c1 [2] 2d c1 [2] 12 dd }

  condition:
    any of them
}