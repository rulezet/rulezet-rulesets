rule TTP_XOR_WriteProcessMemory_5f58 {
  strings:
    $key_5f58 = { 08 2a [2] 3a 08 [2] 3c 3d [2] 12 3d [2] 2d 21 }

  condition:
    any of them
}