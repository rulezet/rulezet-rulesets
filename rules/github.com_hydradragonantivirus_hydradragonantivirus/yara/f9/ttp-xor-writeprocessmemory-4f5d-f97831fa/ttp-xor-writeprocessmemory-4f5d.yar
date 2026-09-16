rule TTP_XOR_WriteProcessMemory_4f5d {
  strings:
    $key_4f5d = { 18 2f [2] 2a 0d [2] 2c 38 [2] 02 38 [2] 3d 24 }

  condition:
    any of them
}