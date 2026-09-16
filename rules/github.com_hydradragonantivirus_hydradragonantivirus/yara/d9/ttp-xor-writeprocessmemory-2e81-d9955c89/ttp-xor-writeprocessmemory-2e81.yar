rule TTP_XOR_WriteProcessMemory_2e81 {
  strings:
    $key_2e81 = { 79 f3 [2] 4b d1 [2] 4d e4 [2] 63 e4 [2] 5c f8 }

  condition:
    any of them
}