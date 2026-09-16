rule TTP_XOR_WriteProcessMemory_5e72 {
  strings:
    $key_5e72 = { 09 00 [2] 3b 22 [2] 3d 17 [2] 13 17 [2] 2c 0b }

  condition:
    any of them
}