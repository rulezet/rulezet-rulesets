rule TTP_XOR_WriteProcessMemory_6a7d {
  strings:
    $key_6a7d = { 3d 0f [2] 0f 2d [2] 09 18 [2] 27 18 [2] 18 04 }

  condition:
    any of them
}