rule TTP_XOR_WriteProcessMemory_63b6 {
  strings:
    $key_63b6 = { 34 c4 [2] 06 e6 [2] 00 d3 [2] 2e d3 [2] 11 cf }

  condition:
    any of them
}