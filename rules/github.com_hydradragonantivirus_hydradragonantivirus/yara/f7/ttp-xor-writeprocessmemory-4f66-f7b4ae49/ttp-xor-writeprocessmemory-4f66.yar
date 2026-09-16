rule TTP_XOR_WriteProcessMemory_4f66 {
  strings:
    $key_4f66 = { 18 14 [2] 2a 36 [2] 2c 03 [2] 02 03 [2] 3d 1f }

  condition:
    any of them
}