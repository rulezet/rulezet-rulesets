rule TTP_XOR_WriteProcessMemory_f6ac {
  strings:
    $key_f6ac = { a1 de [2] 93 fc [2] 95 c9 [2] bb c9 [2] 84 d5 }

  condition:
    any of them
}