rule TTP_XOR_WriteProcessMemory_4e56 {
  strings:
    $key_4e56 = { 19 24 [2] 2b 06 [2] 2d 33 [2] 03 33 [2] 3c 2f }

  condition:
    any of them
}