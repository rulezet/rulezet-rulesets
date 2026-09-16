rule TTP_XOR_WriteProcessMemory_1810 {
  strings:
    $key_1810 = { 4f 62 [2] 7d 40 [2] 7b 75 [2] 55 75 [2] 6a 69 }

  condition:
    any of them
}