rule TTP_XOR_WriteProcessMemory_b0bb {
  strings:
    $key_b0bb = { e7 c9 [2] d5 eb [2] d3 de [2] fd de [2] c2 c2 }

  condition:
    any of them
}