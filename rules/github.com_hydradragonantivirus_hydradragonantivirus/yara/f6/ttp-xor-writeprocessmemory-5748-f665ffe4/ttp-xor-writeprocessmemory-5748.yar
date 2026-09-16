rule TTP_XOR_WriteProcessMemory_5748 {
  strings:
    $key_5748 = { 00 3a [2] 32 18 [2] 34 2d [2] 1a 2d [2] 25 31 }

  condition:
    any of them
}