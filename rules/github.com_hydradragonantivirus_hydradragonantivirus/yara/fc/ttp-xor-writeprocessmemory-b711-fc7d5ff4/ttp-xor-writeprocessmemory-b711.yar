rule TTP_XOR_WriteProcessMemory_b711 {
  strings:
    $key_b711 = { e0 63 [2] d2 41 [2] d4 74 [2] fa 74 [2] c5 68 }

  condition:
    any of them
}