rule TTP_XOR_WriteProcessMemory_0b42 {
  strings:
    $key_0b42 = { 5c 30 [2] 6e 12 [2] 68 27 [2] 46 27 [2] 79 3b }

  condition:
    any of them
}