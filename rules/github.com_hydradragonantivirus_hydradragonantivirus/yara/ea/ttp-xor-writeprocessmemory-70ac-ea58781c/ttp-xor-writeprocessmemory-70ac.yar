rule TTP_XOR_WriteProcessMemory_70ac {
  strings:
    $key_70ac = { 27 de [2] 15 fc [2] 13 c9 [2] 3d c9 [2] 02 d5 }

  condition:
    any of them
}