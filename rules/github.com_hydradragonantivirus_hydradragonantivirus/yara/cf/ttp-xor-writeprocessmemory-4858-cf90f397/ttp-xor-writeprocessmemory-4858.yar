rule TTP_XOR_WriteProcessMemory_4858 {
  strings:
    $key_4858 = { 1f 2a [2] 2d 08 [2] 2b 3d [2] 05 3d [2] 3a 21 }

  condition:
    any of them
}