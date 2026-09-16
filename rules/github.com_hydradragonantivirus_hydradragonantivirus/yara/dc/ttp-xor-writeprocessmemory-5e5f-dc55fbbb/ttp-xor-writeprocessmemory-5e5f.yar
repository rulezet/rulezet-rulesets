rule TTP_XOR_WriteProcessMemory_5e5f {
  strings:
    $key_5e5f = { 09 2d [2] 3b 0f [2] 3d 3a [2] 13 3a [2] 2c 26 }

  condition:
    any of them
}