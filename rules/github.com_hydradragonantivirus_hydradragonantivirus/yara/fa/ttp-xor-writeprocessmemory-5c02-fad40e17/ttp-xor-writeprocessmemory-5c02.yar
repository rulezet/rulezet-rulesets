rule TTP_XOR_WriteProcessMemory_5c02 {
  strings:
    $key_5c02 = { 0b 70 [2] 39 52 [2] 3f 67 [2] 11 67 [2] 2e 7b }

  condition:
    any of them
}