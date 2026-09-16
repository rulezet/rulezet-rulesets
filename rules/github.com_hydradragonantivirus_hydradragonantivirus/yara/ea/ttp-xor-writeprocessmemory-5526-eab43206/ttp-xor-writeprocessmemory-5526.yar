rule TTP_XOR_WriteProcessMemory_5526 {
  strings:
    $key_5526 = { 02 54 [2] 30 76 [2] 36 43 [2] 18 43 [2] 27 5f }

  condition:
    any of them
}