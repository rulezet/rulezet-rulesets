rule TTP_XOR_WriteProcessMemory_76ac {
  strings:
    $key_76ac = { 21 de [2] 13 fc [2] 15 c9 [2] 3b c9 [2] 04 d5 }

  condition:
    any of them
}