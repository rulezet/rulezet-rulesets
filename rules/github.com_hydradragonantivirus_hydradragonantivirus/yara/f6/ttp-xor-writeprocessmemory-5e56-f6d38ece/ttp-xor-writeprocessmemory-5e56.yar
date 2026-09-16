rule TTP_XOR_WriteProcessMemory_5e56 {
  strings:
    $key_5e56 = { 09 24 [2] 3b 06 [2] 3d 33 [2] 13 33 [2] 2c 2f }

  condition:
    any of them
}