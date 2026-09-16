rule TTP_XOR_WriteProcessMemory_706d {
  strings:
    $key_706d = { 27 1f [2] 15 3d [2] 13 08 [2] 3d 08 [2] 02 14 }

  condition:
    any of them
}