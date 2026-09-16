rule TTP_XOR_WriteProcessMemory_7a6d {
  strings:
    $key_7a6d = { 2d 1f [2] 1f 3d [2] 19 08 [2] 37 08 [2] 08 14 }

  condition:
    any of them
}