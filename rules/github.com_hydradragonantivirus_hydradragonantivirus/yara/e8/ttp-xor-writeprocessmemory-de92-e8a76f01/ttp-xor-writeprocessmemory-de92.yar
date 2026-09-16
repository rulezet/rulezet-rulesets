rule TTP_XOR_WriteProcessMemory_de92 {
  strings:
    $key_de92 = { 89 e0 [2] bb c2 [2] bd f7 [2] 93 f7 [2] ac eb }

  condition:
    any of them
}