rule TTP_XOR_WriteProcessMemory_4b72 {
  strings:
    $key_4b72 = { 1c 00 [2] 2e 22 [2] 28 17 [2] 06 17 [2] 39 0b }

  condition:
    any of them
}