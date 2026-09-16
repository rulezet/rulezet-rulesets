rule TTP_XOR_WriteProcessMemory_3d1d {
  strings:
    $key_3d1d = { 6a 6f [2] 58 4d [2] 5e 78 [2] 70 78 [2] 4f 64 }

  condition:
    any of them
}