rule TTP_XOR_WriteProcessMemory_52ac {
  strings:
    $key_52ac = { 05 de [2] 37 fc [2] 31 c9 [2] 1f c9 [2] 20 d5 }

  condition:
    any of them
}