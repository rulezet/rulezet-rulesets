rule TTP_XOR_WriteProcessMemory_70e8 {
  strings:
    $key_70e8 = { 27 9a [2] 15 b8 [2] 13 8d [2] 3d 8d [2] 02 91 }

  condition:
    any of them
}