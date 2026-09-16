rule TTP_XOR_WriteProcessMemory_6a6d {
  strings:
    $key_6a6d = { 3d 1f [2] 0f 3d [2] 09 08 [2] 27 08 [2] 18 14 }

  condition:
    any of them
}