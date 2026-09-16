rule TTP_XOR_WriteProcessMemory_1b72 {
  strings:
    $key_1b72 = { 4c 00 [2] 7e 22 [2] 78 17 [2] 56 17 [2] 69 0b }

  condition:
    any of them
}