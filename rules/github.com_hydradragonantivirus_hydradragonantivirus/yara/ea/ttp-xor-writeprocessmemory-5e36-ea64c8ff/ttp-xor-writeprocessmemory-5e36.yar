rule TTP_XOR_WriteProcessMemory_5e36 {
  strings:
    $key_5e36 = { 09 44 [2] 3b 66 [2] 3d 53 [2] 13 53 [2] 2c 4f }

  condition:
    any of them
}