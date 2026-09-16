rule TTP_XOR_WriteProcessMemory_29a7 {
  strings:
    $key_29a7 = { 7e d5 [2] 4c f7 [2] 4a c2 [2] 64 c2 [2] 5b de }

  condition:
    any of them
}