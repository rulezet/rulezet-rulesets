rule TTP_XOR_WriteProcessMemory_51ac {
  strings:
    $key_51ac = { 06 de [2] 34 fc [2] 32 c9 [2] 1c c9 [2] 23 d5 }

  condition:
    any of them
}