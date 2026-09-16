rule TTP_XOR_WriteProcessMemory_6014 {
  strings:
    $key_6014 = { 37 66 [2] 05 44 [2] 03 71 [2] 2d 71 [2] 12 6d }

  condition:
    any of them
}