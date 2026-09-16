rule TTP_XOR_WriteProcessMemory_7038 {
  strings:
    $key_7038 = { 27 4a [2] 15 68 [2] 13 5d [2] 3d 5d [2] 02 41 }

  condition:
    any of them
}