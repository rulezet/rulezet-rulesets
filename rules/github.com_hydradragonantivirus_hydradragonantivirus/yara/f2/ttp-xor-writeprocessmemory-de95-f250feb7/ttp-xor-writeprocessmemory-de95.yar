rule TTP_XOR_WriteProcessMemory_de95 {
  strings:
    $key_de95 = { 89 e7 [2] bb c5 [2] bd f0 [2] 93 f0 [2] ac ec }

  condition:
    any of them
}