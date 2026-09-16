rule TTP_XOR_WriteProcessMemory_5e7d {
  strings:
    $key_5e7d = { 09 0f [2] 3b 2d [2] 3d 18 [2] 13 18 [2] 2c 04 }

  condition:
    any of them
}