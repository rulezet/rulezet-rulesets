rule TTP_XOR_WriteProcessMemory_22ac {
  strings:
    $key_22ac = { 75 de [2] 47 fc [2] 41 c9 [2] 6f c9 [2] 50 d5 }

  condition:
    any of them
}