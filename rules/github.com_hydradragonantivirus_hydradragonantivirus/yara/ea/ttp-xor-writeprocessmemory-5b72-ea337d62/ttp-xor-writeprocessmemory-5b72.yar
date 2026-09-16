rule TTP_XOR_WriteProcessMemory_5b72 {
  strings:
    $key_5b72 = { 0c 00 [2] 3e 22 [2] 38 17 [2] 16 17 [2] 29 0b }

  condition:
    any of them
}