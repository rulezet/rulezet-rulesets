rule TTP_XOR_WriteProcessMemory_6a4d {
  strings:
    $key_6a4d = { 3d 3f [2] 0f 1d [2] 09 28 [2] 27 28 [2] 18 34 }

  condition:
    any of them
}