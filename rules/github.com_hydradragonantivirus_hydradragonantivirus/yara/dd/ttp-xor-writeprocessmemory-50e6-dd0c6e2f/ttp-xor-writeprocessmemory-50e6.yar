rule TTP_XOR_WriteProcessMemory_50e6 {
  strings:
    $key_50e6 = { 07 94 [2] 35 b6 [2] 33 83 [2] 1d 83 [2] 22 9f }

  condition:
    any of them
}