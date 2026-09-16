rule TTP_XOR_WriteProcessMemory_32ac {
  strings:
    $key_32ac = { 65 de [2] 57 fc [2] 51 c9 [2] 7f c9 [2] 40 d5 }

  condition:
    any of them
}