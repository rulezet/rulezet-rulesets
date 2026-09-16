rule TTP_XOR_WriteProcessMemory_5ef6 {
  strings:
    $key_5ef6 = { 09 84 [2] 3b a6 [2] 3d 93 [2] 13 93 [2] 2c 8f }

  condition:
    any of them
}