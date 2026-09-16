rule TTP_XOR_WriteProcessMemory_de93 {
  strings:
    $key_de93 = { 89 e1 [2] bb c3 [2] bd f6 [2] 93 f6 [2] ac ea }

  condition:
    any of them
}