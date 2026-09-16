rule TTP_XOR_WriteProcessMemory_7070 {
  strings:
    $key_7070 = { 27 02 [2] 15 20 [2] 13 15 [2] 3d 15 [2] 02 09 }

  condition:
    any of them
}