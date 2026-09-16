rule TTP_XOR_WriteProcessMemory_5f00 {
  strings:
    $key_5f00 = { 08 72 [2] 3a 50 [2] 3c 65 [2] 12 65 [2] 2d 79 }

  condition:
    any of them
}