rule TTP_XOR_WriteProcessMemory_6030 {
  strings:
    $key_6030 = { 37 42 [2] 05 60 [2] 03 55 [2] 2d 55 [2] 12 49 }

  condition:
    any of them
}