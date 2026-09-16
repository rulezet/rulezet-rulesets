rule TTP_XOR_WriteProcessMemory_1860 {
  strings:
    $key_1860 = { 4f 12 [2] 7d 30 [2] 7b 05 [2] 55 05 [2] 6a 19 }

  condition:
    any of them
}