rule TTP_XOR_WriteProcessMemory_7050 {
  strings:
    $key_7050 = { 27 22 [2] 15 00 [2] 13 35 [2] 3d 35 [2] 02 29 }

  condition:
    any of them
}