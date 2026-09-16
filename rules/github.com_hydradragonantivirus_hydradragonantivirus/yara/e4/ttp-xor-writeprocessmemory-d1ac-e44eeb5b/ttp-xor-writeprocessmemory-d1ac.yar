rule TTP_XOR_WriteProcessMemory_d1ac {
  strings:
    $key_d1ac = { 86 de [2] b4 fc [2] b2 c9 [2] 9c c9 [2] a3 d5 }

  condition:
    any of them
}