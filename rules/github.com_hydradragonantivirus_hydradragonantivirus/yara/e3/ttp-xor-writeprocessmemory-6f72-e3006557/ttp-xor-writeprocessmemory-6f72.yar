rule TTP_XOR_WriteProcessMemory_6f72 {
  strings:
    $key_6f72 = { 38 00 [2] 0a 22 [2] 0c 17 [2] 22 17 [2] 1d 0b }

  condition:
    any of them
}