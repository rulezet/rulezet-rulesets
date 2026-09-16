rule TTP_XOR_WriteProcessMemory_45ac {
  strings:
    $key_45ac = { 12 de [2] 20 fc [2] 26 c9 [2] 08 c9 [2] 37 d5 }

  condition:
    any of them
}