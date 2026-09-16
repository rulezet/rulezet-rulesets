rule TTP_XOR_WriteProcessMemory_5f68 {
  strings:
    $key_5f68 = { 08 1a [2] 3a 38 [2] 3c 0d [2] 12 0d [2] 2d 11 }

  condition:
    any of them
}