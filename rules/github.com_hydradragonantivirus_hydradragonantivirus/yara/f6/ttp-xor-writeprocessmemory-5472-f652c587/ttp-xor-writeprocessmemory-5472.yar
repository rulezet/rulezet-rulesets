rule TTP_XOR_WriteProcessMemory_5472 {
  strings:
    $key_5472 = { 03 00 [2] 31 22 [2] 37 17 [2] 19 17 [2] 26 0b }

  condition:
    any of them
}