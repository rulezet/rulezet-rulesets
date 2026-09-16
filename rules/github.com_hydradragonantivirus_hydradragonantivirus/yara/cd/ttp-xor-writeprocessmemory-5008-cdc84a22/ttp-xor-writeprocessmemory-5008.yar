rule TTP_XOR_WriteProcessMemory_5008 {
  strings:
    $key_5008 = { 07 7a [2] 35 58 [2] 33 6d [2] 1d 6d [2] 22 71 }

  condition:
    any of them
}