rule TTP_XOR_WriteProcessMemory_a711 {
  strings:
    $key_a711 = { f0 63 [2] c2 41 [2] c4 74 [2] ea 74 [2] d5 68 }

  condition:
    any of them
}