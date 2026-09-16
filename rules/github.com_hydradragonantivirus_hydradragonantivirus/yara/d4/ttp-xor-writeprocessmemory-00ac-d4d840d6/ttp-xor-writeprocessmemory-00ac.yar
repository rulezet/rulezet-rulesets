rule TTP_XOR_WriteProcessMemory_00ac {
  strings:
    $key_00ac = { 57 de [2] 65 fc [2] 63 c9 [2] 4d c9 [2] 72 d5 }

  condition:
    any of them
}