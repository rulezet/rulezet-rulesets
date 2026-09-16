rule TTP_XOR_WriteProcessMemory_6408 {
  strings:
    $key_6408 = { 33 7a [2] 01 58 [2] 07 6d [2] 29 6d [2] 16 71 }

  condition:
    any of them
}