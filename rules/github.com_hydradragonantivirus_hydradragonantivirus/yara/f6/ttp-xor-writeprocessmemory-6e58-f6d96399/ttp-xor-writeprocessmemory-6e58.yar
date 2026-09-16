rule TTP_XOR_WriteProcessMemory_6e58 {
  strings:
    $key_6e58 = { 39 2a [2] 0b 08 [2] 0d 3d [2] 23 3d [2] 1c 21 }

  condition:
    any of them
}