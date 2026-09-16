rule TTP_XOR_WriteProcessMemory_5e2d {
  strings:
    $key_5e2d = { 09 5f [2] 3b 7d [2] 3d 48 [2] 13 48 [2] 2c 54 }

  condition:
    any of them
}