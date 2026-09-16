rule TTP_XOR_WriteProcessMemory_6032 {
  strings:
    $key_6032 = { 37 40 [2] 05 62 [2] 03 57 [2] 2d 57 [2] 12 4b }

  condition:
    any of them
}