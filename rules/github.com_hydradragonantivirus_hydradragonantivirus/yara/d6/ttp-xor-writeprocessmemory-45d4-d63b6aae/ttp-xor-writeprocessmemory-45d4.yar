rule TTP_XOR_WriteProcessMemory_45d4 {
  strings:
    $key_45d4 = { 12 a6 [2] 20 84 [2] 26 b1 [2] 08 b1 [2] 37 ad }

  condition:
    any of them
}