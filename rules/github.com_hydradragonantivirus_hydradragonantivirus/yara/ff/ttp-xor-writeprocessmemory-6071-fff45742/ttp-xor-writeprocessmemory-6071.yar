rule TTP_XOR_WriteProcessMemory_6071 {
  strings:
    $key_6071 = { 37 03 [2] 05 21 [2] 03 14 [2] 2d 14 [2] 12 08 }

  condition:
    any of them
}