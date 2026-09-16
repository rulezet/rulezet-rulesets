rule TTP_XOR_WriteProcessMemory_4e6d {
  strings:
    $key_4e6d = { 19 1f [2] 2b 3d [2] 2d 08 [2] 03 08 [2] 3c 14 }

  condition:
    any of them
}