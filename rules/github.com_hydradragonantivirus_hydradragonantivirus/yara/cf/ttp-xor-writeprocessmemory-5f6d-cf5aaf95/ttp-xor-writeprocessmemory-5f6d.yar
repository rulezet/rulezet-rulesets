rule TTP_XOR_WriteProcessMemory_5f6d {
  strings:
    $key_5f6d = { 08 1f [2] 3a 3d [2] 3c 08 [2] 12 08 [2] 2d 14 }

  condition:
    any of them
}