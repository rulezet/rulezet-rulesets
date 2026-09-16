rule TTP_XOR_WriteProcessMemory_5f06 {
  strings:
    $key_5f06 = { 08 74 [2] 3a 56 [2] 3c 63 [2] 12 63 [2] 2d 7f }

  condition:
    any of them
}