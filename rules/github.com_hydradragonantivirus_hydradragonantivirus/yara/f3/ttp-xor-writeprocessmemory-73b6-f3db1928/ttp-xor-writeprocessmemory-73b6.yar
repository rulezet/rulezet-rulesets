rule TTP_XOR_WriteProcessMemory_73b6 {
  strings:
    $key_73b6 = { 24 c4 [2] 16 e6 [2] 10 d3 [2] 3e d3 [2] 01 cf }

  condition:
    any of them
}