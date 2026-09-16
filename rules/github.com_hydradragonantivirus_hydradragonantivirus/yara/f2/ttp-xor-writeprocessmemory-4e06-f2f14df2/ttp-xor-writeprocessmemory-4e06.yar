rule TTP_XOR_WriteProcessMemory_4e06 {
  strings:
    $key_4e06 = { 19 74 [2] 2b 56 [2] 2d 63 [2] 03 63 [2] 3c 7f }

  condition:
    any of them
}