rule TTP_XOR_WriteProcessMemory_1ba7 {
  strings:
    $key_1ba7 = { 4c d5 [2] 7e f7 [2] 78 c2 [2] 56 c2 [2] 69 de }

  condition:
    any of them
}