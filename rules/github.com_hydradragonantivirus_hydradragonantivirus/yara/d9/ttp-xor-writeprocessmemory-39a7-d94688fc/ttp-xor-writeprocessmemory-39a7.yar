rule TTP_XOR_WriteProcessMemory_39a7 {
  strings:
    $key_39a7 = { 6e d5 [2] 5c f7 [2] 5a c2 [2] 74 c2 [2] 4b de }

  condition:
    any of them
}