rule TTP_XOR_WriteProcessMemory_5668 {
  strings:
    $key_5668 = { 01 1a [2] 33 38 [2] 35 0d [2] 1b 0d [2] 24 11 }

  condition:
    any of them
}