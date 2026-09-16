rule TTP_XOR_WriteProcessMemory_1cac {
  strings:
    $key_1cac = { 4b de [2] 79 fc [2] 7f c9 [2] 51 c9 [2] 6e d5 }

  condition:
    any of them
}