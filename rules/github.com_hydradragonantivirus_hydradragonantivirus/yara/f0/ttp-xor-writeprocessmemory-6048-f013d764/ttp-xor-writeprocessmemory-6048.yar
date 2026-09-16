rule TTP_XOR_WriteProcessMemory_6048 {
  strings:
    $key_6048 = { 37 3a [2] 05 18 [2] 03 2d [2] 2d 2d [2] 12 31 }

  condition:
    any of them
}