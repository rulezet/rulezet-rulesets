rule TTP_XOR_WriteProcessMemory_39a0 {
  strings:
    $key_39a0 = { 6e d2 [2] 5c f0 [2] 5a c5 [2] 74 c5 [2] 4b d9 }

  condition:
    any of them
}