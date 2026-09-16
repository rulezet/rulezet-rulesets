rule TTP_XOR_WriteProcessMemory_4e00 {
  strings:
    $key_4e00 = { 19 72 [2] 2b 50 [2] 2d 65 [2] 03 65 [2] 3c 79 }

  condition:
    any of them
}