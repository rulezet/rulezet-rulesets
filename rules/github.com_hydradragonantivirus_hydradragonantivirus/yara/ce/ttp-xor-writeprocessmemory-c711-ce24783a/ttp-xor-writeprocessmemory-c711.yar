rule TTP_XOR_WriteProcessMemory_c711 {
  strings:
    $key_c711 = { 90 63 [2] a2 41 [2] a4 74 [2] 8a 74 [2] b5 68 }

  condition:
    any of them
}