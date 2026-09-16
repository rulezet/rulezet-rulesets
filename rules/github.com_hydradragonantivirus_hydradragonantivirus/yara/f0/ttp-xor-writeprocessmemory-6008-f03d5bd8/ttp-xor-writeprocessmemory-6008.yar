rule TTP_XOR_WriteProcessMemory_6008 {
  strings:
    $key_6008 = { 37 7a [2] 05 58 [2] 03 6d [2] 2d 6d [2] 12 71 }

  condition:
    any of them
}