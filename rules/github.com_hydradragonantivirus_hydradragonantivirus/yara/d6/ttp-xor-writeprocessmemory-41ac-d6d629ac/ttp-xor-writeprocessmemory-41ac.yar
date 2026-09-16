rule TTP_XOR_WriteProcessMemory_41ac {
  strings:
    $key_41ac = { 16 de [2] 24 fc [2] 22 c9 [2] 0c c9 [2] 33 d5 }

  condition:
    any of them
}