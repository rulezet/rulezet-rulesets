rule TTP_XOR_WriteProcessMemory_ccac {
  strings:
    $key_ccac = { 9b de [2] a9 fc [2] af c9 [2] 81 c9 [2] be d5 }

  condition:
    any of them
}