rule TTP_XOR_WriteProcessMemory_5e42 {
  strings:
    $key_5e42 = { 09 30 [2] 3b 12 [2] 3d 27 [2] 13 27 [2] 2c 3b }

  condition:
    any of them
}