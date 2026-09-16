rule TTP_XOR_WriteProcessMemory_b1ac {
  strings:
    $key_b1ac = { e6 de [2] d4 fc [2] d2 c9 [2] fc c9 [2] c3 d5 }

  condition:
    any of them
}