rule TTP_XOR_WriteProcessMemory_35ac {
  strings:
    $key_35ac = { 62 de [2] 50 fc [2] 56 c9 [2] 78 c9 [2] 47 d5 }

  condition:
    any of them
}