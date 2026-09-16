rule TTP_XOR_WriteProcessMemory_7071 {
  strings:
    $key_7071 = { 27 03 [2] 15 21 [2] 13 14 [2] 3d 14 [2] 02 08 }

  condition:
    any of them
}