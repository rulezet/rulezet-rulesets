rule TTP_XOR_WriteProcessMemory_5f56 {
  strings:
    $key_5f56 = { 08 24 [2] 3a 06 [2] 3c 33 [2] 12 33 [2] 2d 2f }

  condition:
    any of them
}