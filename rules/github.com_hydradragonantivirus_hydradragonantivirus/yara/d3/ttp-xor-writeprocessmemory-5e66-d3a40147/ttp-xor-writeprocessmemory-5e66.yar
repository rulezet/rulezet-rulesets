rule TTP_XOR_WriteProcessMemory_5e66 {
  strings:
    $key_5e66 = { 09 14 [2] 3b 36 [2] 3d 03 [2] 13 03 [2] 2c 1f }

  condition:
    any of them
}