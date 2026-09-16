rule TTP_XOR_WriteProcessMemory_4f2d {
  strings:
    $key_4f2d = { 18 5f [2] 2a 7d [2] 2c 48 [2] 02 48 [2] 3d 54 }

  condition:
    any of them
}