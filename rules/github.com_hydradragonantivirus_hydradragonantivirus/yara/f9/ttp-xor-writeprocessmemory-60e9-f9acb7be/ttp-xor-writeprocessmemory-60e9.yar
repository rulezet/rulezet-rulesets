rule TTP_XOR_WriteProcessMemory_60e9 {
  strings:
    $key_60e9 = { 37 9b [2] 05 b9 [2] 03 8c [2] 2d 8c [2] 12 90 }

  condition:
    any of them
}