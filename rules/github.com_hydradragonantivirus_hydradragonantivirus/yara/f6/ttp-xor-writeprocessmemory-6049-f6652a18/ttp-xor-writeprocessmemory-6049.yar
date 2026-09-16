rule TTP_XOR_WriteProcessMemory_6049 {
  strings:
    $key_6049 = { 37 3b [2] 05 19 [2] 03 2c [2] 2d 2c [2] 12 30 }

  condition:
    any of them
}