rule TTP_XOR_WriteProcessMemory_5e54 {
  strings:
    $key_5e54 = { 09 26 [2] 3b 04 [2] 3d 31 [2] 13 31 [2] 2c 2d }

  condition:
    any of them
}