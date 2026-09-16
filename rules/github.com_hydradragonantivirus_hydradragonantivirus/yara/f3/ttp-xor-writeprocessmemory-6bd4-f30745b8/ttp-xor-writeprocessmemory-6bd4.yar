rule TTP_XOR_WriteProcessMemory_6bd4 {
  strings:
    $key_6bd4 = { 3c a6 [2] 0e 84 [2] 08 b1 [2] 26 b1 [2] 19 ad }

  condition:
    any of them
}