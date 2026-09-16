rule TTP_XOR_WriteProcessMemory_6042 {
  strings:
    $key_6042 = { 37 30 [2] 05 12 [2] 03 27 [2] 2d 27 [2] 12 3b }

  condition:
    any of them
}