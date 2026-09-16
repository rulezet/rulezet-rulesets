rule TTP_XOR_WriteProcessMemory_5cac {
  strings:
    $key_5cac = { 0b de [2] 39 fc [2] 3f c9 [2] 11 c9 [2] 2e d5 }

  condition:
    any of them
}