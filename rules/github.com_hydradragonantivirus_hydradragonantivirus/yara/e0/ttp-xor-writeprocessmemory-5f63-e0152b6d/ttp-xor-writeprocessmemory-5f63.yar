rule TTP_XOR_WriteProcessMemory_5f63 {
  strings:
    $key_5f63 = { 08 11 [2] 3a 33 [2] 3c 06 [2] 12 06 [2] 2d 1a }

  condition:
    any of them
}