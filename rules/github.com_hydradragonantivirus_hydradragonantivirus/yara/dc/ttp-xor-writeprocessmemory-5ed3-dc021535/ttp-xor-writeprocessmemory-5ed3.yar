rule TTP_XOR_WriteProcessMemory_5ed3 {
  strings:
    $key_5ed3 = { 09 a1 [2] 3b 83 [2] 3d b6 [2] 13 b6 [2] 2c aa }

  condition:
    any of them
}