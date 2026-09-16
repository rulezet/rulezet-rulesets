rule TTP_XOR_WriteProcessMemory_6b72 {
  strings:
    $key_6b72 = { 3c 00 [2] 0e 22 [2] 08 17 [2] 26 17 [2] 19 0b }

  condition:
    any of them
}