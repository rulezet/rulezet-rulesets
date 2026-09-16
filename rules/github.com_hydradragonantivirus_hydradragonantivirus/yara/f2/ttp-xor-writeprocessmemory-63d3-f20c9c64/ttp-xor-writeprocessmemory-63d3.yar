rule TTP_XOR_WriteProcessMemory_63d3 {
  strings:
    $key_63d3 = { 34 a1 [2] 06 83 [2] 00 b6 [2] 2e b6 [2] 11 aa }

  condition:
    any of them
}