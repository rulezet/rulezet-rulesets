rule TTP_XOR_WriteProcessMemory_7068 {
  strings:
    $key_7068 = { 27 1a [2] 15 38 [2] 13 0d [2] 3d 0d [2] 02 11 }

  condition:
    any of them
}