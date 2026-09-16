rule TTP_XOR_WriteProcessMemory_5e44 {
  strings:
    $key_5e44 = { 09 36 [2] 3b 14 [2] 3d 21 [2] 13 21 [2] 2c 3d }

  condition:
    any of them
}