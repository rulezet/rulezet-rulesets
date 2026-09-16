rule TTP_XOR_WriteProcessMemory_70e1 {
  strings:
    $key_70e1 = { 27 93 [2] 15 b1 [2] 13 84 [2] 3d 84 [2] 02 98 }

  condition:
    any of them
}