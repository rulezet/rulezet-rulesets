rule TTP_XOR_WriteProcessMemory_5e24 {
  strings:
    $key_5e24 = { 09 56 [2] 3b 74 [2] 3d 41 [2] 13 41 [2] 2c 5d }

  condition:
    any of them
}