rule TTP_XOR_WriteProcessMemory_5f65 {
  strings:
    $key_5f65 = { 08 17 [2] 3a 35 [2] 3c 00 [2] 12 00 [2] 2d 1c }

  condition:
    any of them
}