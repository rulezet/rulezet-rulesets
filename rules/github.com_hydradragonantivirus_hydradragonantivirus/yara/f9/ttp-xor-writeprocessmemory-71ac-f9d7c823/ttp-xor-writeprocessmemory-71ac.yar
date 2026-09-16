rule TTP_XOR_WriteProcessMemory_71ac {
  strings:
    $key_71ac = { 26 de [2] 14 fc [2] 12 c9 [2] 3c c9 [2] 03 d5 }

  condition:
    any of them
}