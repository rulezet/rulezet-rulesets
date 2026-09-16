rule TTP_XOR_WriteProcessMemory_55ac {
  strings:
    $key_55ac = { 02 de [2] 30 fc [2] 36 c9 [2] 18 c9 [2] 27 d5 }

  condition:
    any of them
}