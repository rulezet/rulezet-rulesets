rule TTP_XOR_WriteProcessMemory_4048 {
  strings:
    $key_4048 = { 17 3a [2] 25 18 [2] 23 2d [2] 0d 2d [2] 32 31 }

  condition:
    any of them
}